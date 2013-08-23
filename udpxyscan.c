#define VERBOSE_CURL    0
#define VERBOSE         0

#define USE_BITSTREAM
#undef  PRINT_SI

#define MAX_THREADS		32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>

#include <signal.h>
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>

#include <getopt.h>
#include <stdarg.h>

#if defined( USE_BITSTREAM)
#include <bitstream/mpeg/ts.h>
#include <bitstream/mpeg/psi.h>
#include <bitstream/dvb/si.h>
#include <bitstream/dvb/si_print.h>
#include <bitstream/mpeg/psi_print.h>
#endif

#define max(X,Y)    ((X)>(Y) ? (X):(Y))
#define MAX(X,Y)    ((X)>(Y) ? (X):(Y))
#define min(X,Y)    ((X)<(Y) ? (X):(Y))
#define MIN(X,Y)    ((X)<(Y) ? (X):(Y))
#define READ_U16d(X) (((X[0])<<8) | (X[1]))

#define MAX_PIDS    8192
#define READ_ONCE   7

typedef struct ts_pid_t {
    int i_psi_refcount;
    int8_t i_last_cc;

    /* biTStream PSI section gathering */
    uint8_t *p_psi_buffer;
    uint16_t i_psi_buffer_used;
} ts_pid_t;

typedef struct sid_t {
    uint16_t i_sid, i_pmt_pid;
    uint8_t *p_current_pmt;
} sid_t;

#if defined( USE_BITSTREAM)
typedef struct _memorystruct
{
	char output[ 1024];
} MemoryStruct;
#endif

typedef struct _pulling
{
	char url[1024];
	int used;
	int index;
	long long bytesRead;
	pthread_t pulledThread;

	ts_pid_t p_pids[MAX_PIDS];
	sid_t **pp_sids;
	int i_nb_sids;

#if defined( USE_BITSTREAM)
	PSI_TABLE_DECLARE(pp_current_pat_sections);
	PSI_TABLE_DECLARE(pp_next_pat_sections);

	PSI_TABLE_DECLARE(pp_current_sdt_sections);
	PSI_TABLE_DECLARE(pp_next_sdt_sections);

	MemoryStruct ms;

	int videoCnt;
	int audioCnt;
	int valid_pmt;
	int valid_sdt;

	uint8_t provider[ 256];
	uint8_t service[ 256];

	unsigned char tsBuffer[ (7*188)*32];
	unsigned long fillB;
#endif
} THIS_INSTANCE;

static struct               sigaction sa;
static volatile int         signalFlag;
static int					verbose;
static int					threads = 1;
static int					parse_sdt;

#define MAX_BYTES			(32*1024)
#define BUFFER_SIZE_FILL_QUIT		(1024*1024)

static volatile int			tasksRunning = 0;
static THIS_INSTANCE		pulledFree[ MAX_THREADS];

void Die( char *message)
{
    printf( "Die:%s\n", message); fflush( stdout);
    exit( -1);
}

static void signal_handler( int no )
{
    signalFlag = 1;
}

static char *toSize( long long size)
{
static char string[ 32];

    if( size>1024LL*1024LL*1024LL*1024LL)
        snprintf( string, sizeof( string), "%lldTB      ", size/(1024LL*1024LL*1024LL*1024LL));
    else if( size>1024LL*1024LL*1024LL)
        snprintf( string, sizeof( string), "%lldGB      ", size/(1024LL*1024LL*1024LL));
    else if( size>1024LL*1024LL)
        snprintf( string, sizeof( string), "%lldMB      ", size/(1024LL*1024LL));
    else
        snprintf( string, sizeof( string), "%lld        ", size);

    return &string[0];
}

#if defined( USE_BITSTREAM)
#if defined( PRINT_SI)
static print_type_t i_print_type = PRINT_TEXT;

static void print_wrapper(void *_unused, const char *psz_format, ...)
{
    char psz_fmt[strlen(psz_format) + 2];
    va_list args;
    va_start(args, psz_format);
    strcpy(psz_fmt, psz_format);
    strcat(psz_fmt, "\n");
    vprintf(psz_fmt, args);
}

static char *iconv_append_null(const char *p_string, size_t i_length)
{
    char *psz_string = malloc(i_length + 1);
    memcpy(psz_string, p_string, i_length);
    psz_string[i_length] = '\0';
    return psz_string;
}

static char *iconv_wrapper(void *_unused, const char *psz_encoding,
                           char *p_string, size_t i_length)
{
    return iconv_append_null(p_string, i_length);
}
#endif

static void localDump( unsigned char *buffer, int size)
{
int offset = 0;

    printf( "\r\n");
    while( size) {
    int l;
    
        printf( "%04x: ", offset);
        for( l=0; l<MIN(16,size); l++)
            printf( "%02x ", buffer[l]&255);
        while( l<16) {
            printf( "   ");
            l++;
        }
        for( l=0; l<MIN(16,size); l++)
            printf( "%c", buffer[l]<32 ? '.':buffer[l]&255);
        printf( "\r\n");
        buffer += 16;
        offset += 16;
        size -= MIN(16, size);
    }
}

static void handle_pat( THIS_INSTANCE *thisInstance)
{
    PSI_TABLE_DECLARE(pp_old_pat_sections);
    uint8_t i_last_section = psi_table_get_lastsection(thisInstance->pp_next_pat_sections);
    uint8_t i;

    if (psi_table_validate(thisInstance->pp_current_pat_sections) &&
        psi_table_compare(thisInstance->pp_current_pat_sections, thisInstance->pp_next_pat_sections)) {
        /* Identical PAT. Shortcut. */
        psi_table_free(thisInstance->pp_next_pat_sections);
        psi_table_init(thisInstance->pp_next_pat_sections);
        return;
    }

    /* Switch tables. */
    psi_table_copy(pp_old_pat_sections, thisInstance->pp_current_pat_sections);
    psi_table_copy(thisInstance->pp_current_pat_sections, thisInstance->pp_next_pat_sections);
    psi_table_init(thisInstance->pp_next_pat_sections);

    for (i = 0; i <= i_last_section; i++) {
        uint8_t *p_section = psi_table_get_section(thisInstance->pp_current_pat_sections, i);
        const uint8_t *p_program;
        int j = 0;

        while ((p_program = pat_get_program(p_section, j)) != NULL) {
           const uint8_t *p_old_program = NULL;
            uint16_t i_sid = patn_get_program(p_program);
            uint16_t i_pid = patn_get_pid(p_program);
            j++;

    //printf( "PAT %04x, pmt %04x\r\n",  i_sid, i_pid);

            if (i_sid == 0) {
                if (i_pid != NIT_PID)
                    fprintf(stderr,
                        "NIT is carried on PID %hu which isn't DVB compliant\n",
                        i_pid);
                continue; /* NIT */
            }

            if (!psi_table_validate(pp_old_pat_sections)
                  || (p_old_program =
                      pat_table_find_program(pp_old_pat_sections, i_sid))
                       == NULL
                  || patn_get_pid(p_old_program) != i_pid) {
                sid_t *p_sid;
                int i_pmt;
                if (p_old_program != NULL)
                    thisInstance->p_pids[patn_get_pid(p_old_program)].i_psi_refcount--;
                thisInstance->p_pids[i_pid].i_psi_refcount++;

                for (i_pmt = 0; i_pmt < thisInstance->i_nb_sids; i_pmt++)
                    if (thisInstance->pp_sids[i_pmt]->i_sid == i_sid ||
                        thisInstance->pp_sids[i_pmt]->i_sid == 0)
                        break;

                if (i_pmt == thisInstance->i_nb_sids) {
                    p_sid = malloc(sizeof(sid_t));
                    thisInstance->pp_sids = realloc(thisInstance->pp_sids, ++thisInstance->i_nb_sids * sizeof(sid_t *));
                    thisInstance->pp_sids[i_pmt] = p_sid;
                    p_sid->p_current_pmt = NULL;
                }
                else
                    p_sid = thisInstance->pp_sids[i_pmt];

                p_sid->i_sid = i_sid;
                p_sid->i_pmt_pid = i_pid;
            }
        }
    }

    if (psi_table_validate(pp_old_pat_sections)) {
        i_last_section = psi_table_get_lastsection( pp_old_pat_sections );
        for (i = 0; i <= i_last_section; i++) {
            uint8_t *p_section = psi_table_get_section(pp_old_pat_sections, i);
            const uint8_t *p_program;
            int j = 0;

            while ((p_program = pat_get_program(p_section, j)) != NULL) {
                uint16_t i_sid = patn_get_program(p_program);
                j++;

                if (i_sid == 0)
                    continue; /* NIT */

                if (pat_table_find_program(thisInstance->pp_current_pat_sections, i_sid)
                      == NULL) {
                    int i_pmt;
                    for (i_pmt = 0; i_pmt < thisInstance->i_nb_sids; i_pmt++)
                        if (thisInstance->pp_sids[i_pmt]->i_sid == i_sid) {
                            thisInstance->pp_sids[i_pmt]->i_sid = 0;
                            free(thisInstance->pp_sids[i_pmt]->p_current_pmt);
                            thisInstance->pp_sids[i_pmt]->p_current_pmt = NULL;
                            break;
                        }
                }
            }
        }

        psi_table_free(pp_old_pat_sections);
    }
}

static void handle_pat_section(uint16_t i_pid, uint8_t *p_section, THIS_INSTANCE *thisInstance)
{
    if (i_pid != PAT_PID || !pat_validate(p_section)) {
        free(p_section);
        return;
    }

    if (!psi_table_section(thisInstance->pp_next_pat_sections, p_section))
        return;

    handle_pat( thisInstance);
}

static int localFind( uint8_t *es, unsigned char type)
{
int len;

    es++;               // 0x06
    es++;               // Pid
    es++;               // Pid
    len = *es++<<8;
    len |= *es++;
    len &= 0xfff;
//    printf( "Looking for %02x (%d) - ", type, len); 
    while( len)
    {
//        printf( "[%02x %2d]", es[0], es[1]);
        if( *es==type) {
//            printf( "FOUND\r\n");
            return 1;
        }
        len -= es[1]+2;
        es  += es[1]+2;
    }
//    printf( "\r\n");
    
    return 0;
}

static int pmt_count(uint8_t *p_pmt, THIS_INSTANCE *thisInstance)
{
    uint8_t *p_es;
    uint8_t j = 0;
    int cnt = 0;
	int videoCnt = 0;
	int audioCnt = 0;
	MemoryStruct *ms = &thisInstance->ms;

    while ((p_es = pmt_get_es(p_pmt, j)) != NULL) {
        sprintf( ms->output+strlen( ms->output), "(%04x,%02x)", pmtn_get_pid(p_es), pmtn_get_streamtype(p_es));
        switch( pmtn_get_streamtype(p_es))
        {
            // Video
            case 1:
            case 2:
            case 27:
                cnt |= 1;
				videoCnt++;
                break;

            // Audio
            case 3:
            case 4:
            case 15:
                cnt |= 2;
				audioCnt++;
                break;

            // Teletext
            case 6:
//                printf( "\r\n");
                if( localFind( p_es, 0x45))
                    cnt |= 0x80;   // VBI
                else if( localFind( p_es, 0x46))
                    cnt |= 0x40;   // VBI Teletext
                else if( localFind( p_es, 0x56))
                    cnt |= 8;   // Teletext
                else if( localFind( p_es, 0x59))
                    cnt |= 4;   // Subtitles
                else if( localFind( p_es, 0x6a)) {
                    cnt |= 2;   // AC3
    				audioCnt++;
                }
                else if( localFind( p_es, 0x7a)) {
                    cnt |= 2;   // AC3
    				audioCnt++;
                }
                else if( localFind( p_es, 0x7b)) {
                    cnt |= 2;   // AC3
    				audioCnt++;
                }
                else if( localFind( p_es, 0x7c)) {
                    cnt |= 2;   // AC3
    				audioCnt++;
                }
                else if( localFind( p_es, 0x7c)) {
                    cnt |= 2;   // AC3
    				audioCnt++;
                }
                else
                    localDump( p_es, 64);                
                break;
        }
        j++;
    }
    while( j<5) {
        sprintf( ms->output+strlen( ms->output), "         ");
        j++;
    }

	thisInstance->videoCnt = videoCnt;
	thisInstance->audioCnt = audioCnt;

//    printf( "(%02x,%d,%d) ", cnt, audioCnt, videoCnt);

    return cnt;
}

static void handle_pmt(uint16_t i_pid, uint8_t *p_pmt, THIS_INSTANCE *thisInstance)
{
    uint16_t i_sid = pmt_get_program(p_pmt);
    sid_t *p_sid;
    int i;

    /* we do this before checking the service ID */
    if (!pmt_validate(p_pmt)) {
        free(p_pmt);
        return;
    }

    for (i = 0; i < thisInstance->i_nb_sids; i++)
        if (thisInstance->pp_sids[i]->i_sid && thisInstance->pp_sids[i]->i_sid == i_sid)
            break;

    if (i == thisInstance->i_nb_sids) {
        p_sid = malloc(sizeof(sid_t));
        thisInstance->pp_sids = realloc(thisInstance->pp_sids, ++thisInstance->i_nb_sids * sizeof(sid_t *));
        thisInstance->pp_sids[i] = p_sid;
        p_sid->i_sid = i_sid;
        p_sid->i_pmt_pid = i_pid;
        p_sid->p_current_pmt = NULL;
    } else {
        p_sid = thisInstance->pp_sids[i];
        if (i_pid != p_sid->i_pmt_pid) {
        }
    }

    if (p_sid->p_current_pmt != NULL &&
        psi_compare(p_sid->p_current_pmt, p_pmt)) {
        /* Identical PMT. Shortcut. */
        free(p_pmt);
        return;
    }

    free(p_sid->p_current_pmt);
    p_sid->p_current_pmt = p_pmt;

#if defined( PRINT_SI)
    pmt_print(p_pmt, print_wrapper, NULL, iconv_wrapper, NULL, i_print_type);
#endif

    thisInstance->valid_pmt = pmt_count(p_pmt, thisInstance);
}

static void _sdt_do_desc( THIS_INSTANCE *thisInstance, uint8_t *p_descl, uint16_t i_length)
{
    uint16_t j = 0;
    uint8_t *p_desc;

    while ((p_desc = descl_get_desc(p_descl, i_length, j)) != NULL) {
        uint8_t i_tag = desc_get_tag(p_desc);
        uint8_t i_len;
        uint8_t *p;
        j++;

        switch (i_tag) {
			case 0x48:
                p = desc48_get_provider(p_desc,&i_len);
				memcpy( thisInstance->provider, p, i_len);
				thisInstance->provider[ i_len] = 0;
                p = desc48_get_service(p_desc,&i_len);
				memcpy( thisInstance->service, p, i_len);
				thisInstance->service[ i_len] = 0;
				//printf( "{'%s' '%s'}", thisInstance->provider, thisInstance->service);
				break;

			default:
				//printf( "[%02x] ", i_tag);
				break;
		}
	}
}

static inline void sdt_do_desc( THIS_INSTANCE *thisInstance, uint8_t *p_descs)
{
    _sdt_do_desc(thisInstance, p_descs + DESCS_HEADER_SIZE, descs_get_length(p_descs));
}

static void sdt_do_table( THIS_INSTANCE *thisInstance, uint8_t **pp_sections)
{
    uint8_t i_last_section = psi_table_get_lastsection(pp_sections);
    uint8_t i;

    for (i = 0; i <= i_last_section; i++) {
        uint8_t *p_section = psi_table_get_section(pp_sections, i);
        uint8_t *p_service;
        int j = 0;

        while ((p_service = sdt_get_service(p_section, j)) != NULL) {
            j++;
			sdt_do_desc(thisInstance, sdtn_get_descs(p_service));
		}
    }
}


static void handle_sdt( THIS_INSTANCE *thisInstance)
{
    if (psi_table_validate(thisInstance->pp_current_sdt_sections) &&
        psi_table_compare(thisInstance->pp_current_sdt_sections, thisInstance->pp_next_sdt_sections)) {
        /* Identical SDT. Shortcut. */
        psi_table_free(thisInstance->pp_next_sdt_sections);
        psi_table_init(thisInstance->pp_next_sdt_sections);
        return;
    }

    if (!sdt_table_validate(thisInstance->pp_next_sdt_sections)) {
        psi_table_free(thisInstance->pp_next_sdt_sections);
        psi_table_init(thisInstance->pp_next_sdt_sections);
        return;
    }

    /* Switch tables. */
    psi_table_free(thisInstance->pp_current_sdt_sections);
    psi_table_copy(thisInstance->pp_current_sdt_sections, thisInstance->pp_next_sdt_sections);
    psi_table_init(thisInstance->pp_next_sdt_sections);

	sdt_do_table(thisInstance, thisInstance->pp_current_sdt_sections);

#if defined( PRINT_SI)
    sdt_table_print(thisInstance->pp_current_sdt_sections, print_wrapper, NULL,
                    iconv_wrapper, NULL, i_print_type);
#endif

	thisInstance->valid_sdt = 1;
}

static void handle_sdt_section(uint16_t i_pid, uint8_t *p_section, THIS_INSTANCE *thisInstance)
{
    if (i_pid != SDT_PID || !sdt_validate(p_section)) {
        free(p_section);
        return;
    }

    if (!psi_table_section(thisInstance->pp_next_sdt_sections, p_section))
        return;

    handle_sdt( thisInstance);
}

static void handle_section(uint16_t i_pid, uint8_t *p_section, THIS_INSTANCE *thisInstance)
{
    uint8_t i_table_id = psi_get_tableid(p_section);

    if (!psi_validate(p_section)) {
        free(p_section);
        return;
    }

    switch (i_table_id) {
    case PAT_TABLE_ID:
        handle_pat_section(i_pid, p_section, thisInstance);
        break;

//    case CAT_TABLE_ID:
//        handle_cat_section(i_pid, p_section, thisInstance);
//        break;

//    case TSDT_TABLE_ID:
//        handle_tsdt_section(i_pid, p_section, thisInstance);
//        break;

    case PMT_TABLE_ID:
        handle_pmt(i_pid, p_section, thisInstance);
        break;

//    case NIT_TABLE_ID_ACTUAL:
//        handle_nit_section(i_pid, p_section, thisInstance);
//        break;

//    case BAT_TABLE_ID:
//        handle_bat_section(i_pid, p_section, thisInstance);
//        break;

    case SDT_TABLE_ID_ACTUAL:
        handle_sdt_section(i_pid, p_section, thisInstance);
        break;

//    case TDT_TABLE_ID:
//        handle_tdt_section(i_pid, p_section, thisInstance);
//        break;

//    case TOT_TABLE_ID:
//        handle_tot_section(i_pid, p_section, thisInstance);
//        break;

//    case RST_TABLE_ID:
//        handle_rst_section(i_pid, p_section, thisInstance);
//        break;

//    case DIT_TABLE_ID:
//        handle_dit_section(i_pid, p_section, thisInstance);
//        break;

//    case SIT_TABLE_ID:
//        handle_sit_section(i_pid, p_section, thisInstance);
//        break;

    default:
//        if (i_table_id == EIT_TABLE_ID_PF_ACTUAL ||
//           (i_table_id >= EIT_TABLE_ID_SCHED_ACTUAL_FIRST &&
//            i_table_id <= EIT_TABLE_ID_SCHED_ACTUAL_LAST)) {
//            handle_eit_section(i_pid, p_section, thisInstance);
//            break;
//        }

        free( p_section );
        break;
    }
}

static void handle_psi_packet(uint8_t *p_ts, THIS_INSTANCE *thisInstance)
{
    uint16_t i_pid = ts_get_pid(p_ts);
    ts_pid_t *p_pid = &thisInstance->p_pids[i_pid];
    uint8_t i_cc = ts_get_cc(p_ts);
    const uint8_t *p_payload;
    uint8_t i_length;

    if (ts_check_duplicate(i_cc, p_pid->i_last_cc) || !ts_has_payload(p_ts))
        return;

    if (p_pid->i_last_cc != -1
          && ts_check_discontinuity(i_cc, p_pid->i_last_cc))
        psi_assemble_reset(&p_pid->p_psi_buffer, &p_pid->i_psi_buffer_used);

    p_payload = ts_section(p_ts);
    i_length = p_ts + TS_SIZE - p_payload;

    if (!psi_assemble_empty(&p_pid->p_psi_buffer, &p_pid->i_psi_buffer_used)) {
        uint8_t *p_section = psi_assemble_payload(&p_pid->p_psi_buffer,
                                                 &p_pid->i_psi_buffer_used,
                                                  &p_payload, &i_length);
        if (p_section != NULL)
            handle_section(i_pid, p_section, thisInstance);
    }

    p_payload = ts_next_section( p_ts );
    i_length = p_ts + TS_SIZE - p_payload;

    while (i_length) {
        uint8_t *p_section = psi_assemble_payload(&p_pid->p_psi_buffer,
                                                  &p_pid->i_psi_buffer_used,
                                                  &p_payload, &i_length);
        if (p_section != NULL)
            handle_section(i_pid, p_section, thisInstance);
    }
}
#endif

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *_pulling)
{
THIS_INSTANCE *thisOne = _pulling;
size_t realsize = size * nmemb;
#if defined( USE_BITSTREAM)
unsigned char *b;
#endif

    if( signalFlag)
		return 0;

	thisOne->bytesRead += realsize;

#if defined( USE_BITSTREAM)
	if( thisOne->bytesRead>(BUFFER_SIZE_FILL_QUIT)) {
		signalFlag = 2;
	}

	b = thisOne->tsBuffer;

	memcpy( b+thisOne->fillB, contents, realsize);
	thisOne->fillB = realsize;

	while( thisOne->fillB>=7*188) {
	int synced = b[0*188]==0x47 && b[1*188]==0x47 && b[2*188]==0x47 
				  && b[3*188]==0x47 && b[4*188]==0x47 && b[5*188]==0x47 
				  && b[6*188]==0x47;

		if( synced) {
		int ll;

			for( ll=0; ll<7; ll++) {
			uint16_t i_pid = ts_get_pid( b);
			ts_pid_t *p_pid = &thisOne->p_pids[i_pid];

				if (p_pid->i_psi_refcount) {
					handle_psi_packet( b, thisOne);
					if( !parse_sdt) {
                        if( thisOne->valid_pmt) {
                            return 0;
                        }
                    }
                    else {
                        if( thisOne->valid_pmt && thisOne->valid_sdt) {
                            return 0;
                        }
					}
				}
				p_pid->i_last_cc = ts_get_cc( b);
				b += 188;
				thisOne->fillB -= 188;
			}
		}
		else {
			do {
				b++;
				thisOne->fillB--;
			} while( thisOne->fillB>187 && b[0]!=0x47);
		}
	}
	memcpy( thisOne->tsBuffer, b, thisOne->fillB);
#else
	if( thisOne->bytesRead>MAX_BYTES)
		return 0;
#endif

    return realsize;
}

static void *pullThread( void *_pulling)
{
THIS_INSTANCE *thisInstance = _pulling;
CURL *curl;
CURLcode res;
#if defined( USE_BITSTREAM)
int i;

    memset(thisInstance->p_pids, 0, sizeof(thisInstance->p_pids));

    for (i = 0; i < MAX_PIDS; i++) {
        thisInstance->p_pids[i].i_last_cc = -1;
        psi_assemble_init( &thisInstance->p_pids[i].p_psi_buffer,
                           &thisInstance->p_pids[i].i_psi_buffer_used );
    }

    psi_table_init(thisInstance->pp_current_pat_sections);
    psi_table_init(thisInstance->pp_current_sdt_sections);

    thisInstance->p_pids[PAT_PID].i_psi_refcount++;
//    thisInstance->p_pids[CAT_PID].i_psi_refcount++;
//    thisInstance->p_pids[TSDT_PID].i_psi_refcount++;
//    thisInstance->p_pids[NIT_PID].i_psi_refcount++;
//    thisInstance->p_pids[BAT_PID].i_psi_refcount++;
	if( parse_sdt) {
        thisInstance->p_pids[SDT_PID].i_psi_refcount++;
    }
//    thisInstance->p_pids[EIT_PID].i_psi_refcount++;
//    thisInstance->p_pids[TDT_PID].i_psi_refcount++;
//    thisInstance->p_pids[RST_PID].i_psi_refcount++;
//    thisInstance->p_pids[DIT_PID].i_psi_refcount++;
//    thisInstance->p_pids[SIT_PID].i_psi_refcount++;
#endif

	if( verbose) {
		printf( "Pulling %s\r\n", (char *)thisInstance->url); // , inet_ntoa(passed->echoclient.sin_addr)); fflush( stdout);
	}

	strcpy( thisInstance->provider, "<unknown>");
	strcpy( thisInstance->service, "<unknown>");
	tasksRunning++;
	thisInstance->used++;
    curl = curl_easy_init();
   	if( curl) {
   	    curl_easy_setopt(curl, CURLOPT_URL, (char *)thisInstance->url);
//       	curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
   	    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)_pulling);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, VERBOSE_CURL);
        res = curl_easy_perform(curl);
		if( thisInstance->bytesRead) {
			printf( "#EXTNF:0,%s (%s)\r\n%s\r\n", thisInstance->service, thisInstance->provider, thisInstance->url);
   	    curl_easy_cleanup(curl);
		}
   	}
    if( verbose) {
		printf( "Pulled  %s (%d) %s\r\n", (char *)thisInstance->url, res, toSize( thisInstance->bytesRead)); fflush( stdout);
	}

#if defined( USE_BITSTREAM)
    for (i = 0; i < thisInstance->i_nb_sids; i++)
    {
        free( thisInstance->pp_sids[i]->p_current_pmt);
        free( thisInstance->pp_sids[i]);
    }

    free( thisInstance->pp_sids);
    thisInstance->i_nb_sids = 0;
    thisInstance->pp_sids = NULL;

    psi_table_free(thisInstance->pp_current_pat_sections);
    psi_table_free(thisInstance->pp_current_sdt_sections);
#endif

	thisInstance->used = 0;
	tasksRunning--;

	return NULL;
}

int main(int i_argc, char **pp_argv)
{
char *url = NULL;
char *mask = NULL;
int error;
int count = 0;
int c;

	if( i_argc==1) {
        printf( "usage: %s -u <url> -m <url mask>\r\n", pp_argv[0]);
		exit( -1);	
	}

    static const struct option long_options[] =
    {
        { "url",       required_argument, NULL, 'u' },
        { "threads",   required_argument, NULL, 't' },
        { "mask",      required_argument, NULL, 'm' },
        { "parse sdt", no_argument,       NULL, 's' },
        { "verbose",   no_argument,       NULL, 'v' },
        { "help",      no_argument,       NULL, 'h' },
        { 0, 0, 0, 0 }
	};
		
    while ( (c = getopt_long(i_argc, pp_argv, "u:t:m:svh", long_options, NULL)) != -1 )
    {
        switch ( c )
        {
        case 'u':
			url = optarg;
			break;

		case 't':
            threads = strtol( optarg, NULL, 0 );
			threads = min( threads, MAX_THREADS);
			break;

        case 'm':
			mask = optarg;
			break;

		case 's':
			parse_sdt = 1;
			break;

		case 'v':
			verbose = 1;
			break;

        case 'h':
        default:
	        printf( "usage: %s -u <url> -m <url mask>\r\n", pp_argv[0]);
			break;

        }
    }

	if( !url || !mask)
		exit( -2);

#if 0
	switch( argc) {
		case 3:
			mask = strdup( argv[2]);
			url = strdup( argv[1]);
			break;

		case 1:
//			url = strdup( "http://37.139.23.84:25000/udp/239.255.1.");
//			mask = strdup( "%d:5004");
			url = strdup( "http://5.158.80.12/udp/239.100.202.");
			mask = strdup( "%d:1234?key=SW-kvSxOfO3NvzofzZg1Cw");
			break;

		default:
			printf( "usage: %s <url> <url mask>\r\n", argv[0]);
			exit( -1);	
	}
#endif

    // prepare to call sigaction()
    sa.sa_handler = signal_handler;
    sa.sa_flags   = SA_RESTART;
    sigemptyset( &sa.sa_mask );
    // catch ctrl+C
    sigaction( SIGINT, &sa, 0 );

    /* Must initialize libcurl before any threads are started */
    curl_global_init(CURL_GLOBAL_ALL);

    signal(SIGPIPE, SIG_IGN);

	do {
	int free;

		for( free=0; pulledFree[ free].used && free<threads; free++)
			;
		if( free<threads) {
			memset( &pulledFree[ free], 0, sizeof( THIS_INSTANCE));
			pulledFree[ free].bytesRead = 0;
			pulledFree[ free].index = count;
			strcpy( pulledFree[ free].url, url);
			sprintf( pulledFree[ free].url+strlen( pulledFree[ free].url), mask, count);
			pulledFree[ free].used = 1;
			error = pthread_create( &pulledFree[ free].pulledThread, NULL, pullThread, (void *)&pulledFree[ free]);
			if( !error) {
				pthread_detach( pulledFree[ free].pulledThread);
				count++;
			}
			else {
				pulledFree[ free].used = 0;
				printf( "Could not start task\r\n");
				count--;
			}
		}
		else {
			sleep( 1);
		}
	} while( count<256 && !signalFlag);

	if( tasksRunning) {
		while( tasksRunning) {
			printf( "Waiting for tasks to close %3d                \r", tasksRunning); fflush( stdout);
			sleep(1);
		}
	}

	curl_global_cleanup();

	exit( EXIT_SUCCESS);
}

