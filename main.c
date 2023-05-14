/**
 * My C implementation of a DNS resolver.
 *
 * Follows https://implement-dns.wizardzines.com/
 *
 * This is a tiny DNS resolver that implements a very limited subset of all the DNS stuff (there's a lot). The
 * aforementioned guide was a good help in structuring the code (which you will definitely see if you follow).
 * A lot of complication and cruff are added because of C and that I did not want to use too many builtins.
 *
 * This is meant as a pedagogic exercise both for the writer and the reader. Nothing in this subset of feature is
 * inherently complicated, but in a C implementation a lot needs to line up to be functional. I tried to do my
 * best w.r.t safety, but I'm sure this is not safe. It was definitely interesting writing a bunch of vulnerabilities
 * and patch them up. There's an easy out of bound read that can be performed by a malicious actor on a vulnerable
 * program (it's identified in the code).
 *
 * On the blog post, some exercises were left to the reader. I have not implemented them except for the recursion
 * attack. The DNS server exercise is fairly trivial since we can forward directly the messages we are receiving
 * to another server (unless we have a cache, then it gets interesting).
 *
 * This is coded for linux, but I think with a few ifdefs and an init function you can get it working on windows.
 *
 * Sample usage:
 * ```shell
 * $ dns google.com
 *   Query for 'google.com': 172.217.13.206
 * ```
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define IP_BYTES_TO_LONG(a, b, c, d) (((d) << 24) | ((c) << 16) | ((b) << 8) | (a))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define IP_BYTES_TO_LONG(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#else
#error Unknown byte order
#endif

#define TYPE_A 1
#define TYPE_NS 2

#define CLASS_IN 1
#define FLAGS_RECUR (1 << 8)

#define DNS_MAX_DOMAIN_LENGTH 253
#define DNS_DOMAIN_COMPRESSION_FLAG (3 << 6)

#define DNS_NAME_MAX_DEPTH 20
#define DNS_MAX_QUERY_DEPTH 20

// Uncomment for the step by step resolution
//#define VERBOSE

#define error(s) {printf(s); exit(1);}

const struct in_addr DEFAULT_RESOLVER = {
        .s_addr = IP_BYTES_TO_LONG(198, 41, 0, 4)
};

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t n_questions;
    uint16_t n_answers;
    uint16_t n_authorities;
    uint16_t n_additionals;
} dns_header_t;

typedef struct {
    char *message;
    uint16_t type;
    uint16_t class;
} dns_question_t;

typedef struct {
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    uint8_t *bytes;
} dns_record_t;

typedef struct {
    dns_header_t header;
    dns_question_t *questions;
    dns_record_t *answers;
    dns_record_t *authorities;
    dns_record_t *additionals;
} dns_packet_t;

dns_header_t dns_header_init() {
    dns_header_t result;
    memset((void *) &result, 0, sizeof(dns_header_t));
    return result;
}

void dns_header_destroy(__attribute__((unused)) dns_header_t *header) {
    // nothing
}

void dns_question_init(dns_question_t *question) {
    memset(question, 0, sizeof(dns_question_t));
}

void dns_question_destroy(dns_question_t *question) {
    if (question->message) {
        free(question->message);
        question->message = NULL;
    }
}

void dns_record_init(dns_record_t *record) {
    memset(record, 0, sizeof(dns_record_t));
}

void dns_record_destroy(dns_record_t *record) {
    if (record->bytes) {
        free(record->bytes);
        record->bytes = NULL;
    }

    if (record->name) {
        free(record->name);
        record->name = NULL;
    }
}

void write_uint16_network(uint16_t v, uint8_t *buff) {
    uint16_t reversed = htons(v);
    buff[0] = reversed & 0xFF;
    buff[1] = (reversed >> 8) & 0xFF;
}

/**
 * Fill a byte array in network order to contain the DNS request header
 *
 * @param header the header to encode
 * @param buff the buffer to fill
 */
void dns_header_encode(dns_header_t *header, uint8_t *buff) {
    uint16_t *field_ptr = (uint16_t *) header;

    for (size_t i = 0; i < sizeof(dns_header_t) / sizeof(uint16_t); ++i) {
        write_uint16_network(field_ptr[i], buff + (i * 2));
    }
}

/**
 * Fill a DNS header from a buffer. Assumes the buffer has enough
 * length.
 *
 * @param header the header
 * @param buff the buffer
 * @param buff_l the buffer length
 */
size_t dns_header_decode(dns_header_t *header, const uint8_t *buff, size_t buff_l) {

    if (buff_l < sizeof(dns_header_t)) {
        error("Not enough data to decode a DNS header. Aborting.")
    }

    uint16_t *field_ptr = (uint16_t *) header;

    for (size_t i = 0; i < sizeof(dns_header_t) / sizeof(uint16_t); ++i) {
        // SHORT_TO_NETWORK is its own inverse :)
        // We force the usage to be portable, since we could be on a big-endian machine
        field_ptr[i] = htons((buff[i * 2 + 1] << 8) | buff[i * 2]);
    }

    return sizeof(dns_header_t);
}

/**
 * Fill a byte array in network order to encode the DNS question
 *
 * @param question the question to encode
 */
bool dns_question_encode(dns_question_t *question, uint8_t *buff) {
    if (!question->message) {
        return false;
    }

    size_t actual_message_length = strlen(question->message) + 1;

    // strcpy copies the sentinel
    strcpy((char *) buff, question->message);
    size_t i = actual_message_length;

    write_uint16_network(question->type, buff + i);
    write_uint16_network(question->class, buff + i + 2);

    return true;
}

/**
 * Encode the domain name in ASCII into the given buffer.
 *
 * **WARNING**
 * This assumes that every part of the domain name is at most 254 characters. I don't know
 * what the DNS spec allows.
 *
 * @param ascii_domain
 * @param buff
 */
char *dns_name_encode(const char *ascii_domain) {
    // WARNING! this assumes that the length of each part is below 255, because we count them
    // as one byte each.

    size_t total_length = 2 + strlen(ascii_domain); // initial number and the trailing 0

    // Prep the final string
    uint8_t *buff = malloc(total_length);
    buff[total_length - 1] = '\0';

    uint8_t part_len = 0;
    uint8_t stamp_pos = 0;
    for (size_t i = 0; ascii_domain[i] != '\0'; ++i) {
        uint8_t chr = ascii_domain[i];
        if (chr == '.') {
            buff[stamp_pos] = part_len;
            stamp_pos = i + 1;
            part_len = 0;
            continue;
        } else if ((part_len += 1) >= DNS_MAX_DOMAIN_LENGTH) {
            error("Domain name too long. Domain part exceeds the maximum length.")
        }

        buff[i + 1] = chr;
    }

    buff[stamp_pos] = part_len;

    return (char *) buff;
}

/**
 * DNS name decoding, with compression support
 *
 * @param buff the full response buffer
 * @param buff_l the length of the full response buffer
 * @param i position to where to read in buff
 * @param c name to decode
 * @param w where to write in c
 * @return how many characters we have advanced in the buffer
 */
size_t dns_name_decode(const uint8_t *buff, size_t buff_l, size_t *i, char *c, size_t *w, uint8_t recursion_credits) {
    if (recursion_credits == 0) {
        printf("Failed to decode the name -- maximum recursion depth limit exceeded.");
        exit(1);
    }

    if (*i >= buff_l) {
        error("Cannot decode the DNS name, not enough room in the buffer")
    }

    while (buff[*i] != '\0') {
        uint8_t length = buff[*i];
        *i += 1;

        if (*i >= buff_l) {
            error("Cannot decode the DNS name, not enough room in the buffer")
        }

        if (length & DNS_DOMAIN_COMPRESSION_FLAG) {
            uint16_t ptr = (length & (~DNS_DOMAIN_COMPRESSION_FLAG)) << 8 | buff[*i];
            // Save and restore the pointer for the recursive call
            uint16_t curr = *i;

            if (ptr >= buff_l) {
                // That would be a clever way to read wherever
                error("Cannot decode recursively the domain, pointing outside of the buffer.")
            }

            *i = ptr;
            dns_name_decode(buff, buff_l, i, c, w, recursion_credits - 1);
            *i = curr;
            break;
        }

        // Check for length before memcpy
        if (*i + length > buff_l) {
            error("Cannot decode the DNS name, not enough room in the buffer")
        }

        // Not recursive, write the chunk and increment the values
        memcpy(c + *w, buff + *i, length);
        *i += length;

        if (buff[*i] != '\0') {
            c[*w + length] = '.';
            *w += 1 + length;
        }
    }

    *i += 1;

    return 0;
}

void dns_question_decode(dns_question_t *question, uint8_t *buff, size_t buff_l, size_t *i) {
    question->message = malloc(DNS_MAX_DOMAIN_LENGTH + 1);
    size_t w = 0;

    dns_name_decode(buff, buff_l, i, question->message, &w, DNS_NAME_MAX_DEPTH);

    buff += *i;

    if (*i + 3 >= buff_l) {
        error("Not enough data in buffer to decode the question")
    }

    question->type = htons(buff[1] << 8 | buff[0]);
    question->class = htons(buff[3] << 8 | buff[2]);

    *i += 4;
}

/**
 * Decode a DNS record
 *
 * The buffer of data
 *
 * @param record
 * @param buff
 * @param buff_l
 * @param i where to start reading in the buffer i
 */
void dns_record_decode(dns_record_t *record, const uint8_t *buff, size_t buff_l, size_t *i) {
    record->name = (char *) malloc(DNS_MAX_DOMAIN_LENGTH + 1);
    size_t w = 0;
    dns_name_decode(buff, buff_l, i, record->name, &w, DNS_NAME_MAX_DEPTH);

    if (*i + 9 >= buff_l) {
        error("Failed to decode the DNS record, not enough data")
    }

    const uint8_t *buff_p = buff + *i;
    record->type = htons(buff_p[1] << 8 | buff_p[0]);
    record->class = htons(buff_p[3] << 8 | buff_p[2]);
    record->ttl = htonl(buff_p[7] << 24 | buff_p[6] << 16 | buff_p[5] << 8 | buff_p[4]);
    record->data_len = htons(buff_p[9] << 8 | buff_p[8]);

    *i += 10;

    if (record->type == TYPE_NS) {

        record->bytes = malloc(DNS_MAX_DOMAIN_LENGTH + 1);
        w = 0;
        dns_name_decode(buff, buff_l, i, (char *) record->bytes, &w, DNS_NAME_MAX_DEPTH);

        return;
    }

    if (record->data_len) {
        if (*i + record->data_len > buff_l) {
            error("Not enough data to fill the data field of the dns record.")
        }

        record->bytes = malloc(record->data_len);
        memcpy(record->bytes, buff + *i, record->data_len);

        *i += record->data_len;

        return;
    }

    record->bytes = NULL;
}

dns_packet_t *dns_packet_create(uint8_t *buff, size_t buff_l) {
    dns_packet_t *pak = malloc(sizeof(dns_packet_t));
    memset((void *) pak, 0, sizeof(dns_packet_t));

    size_t i = dns_header_decode(&pak->header, buff, buff_l);

    uint16_t n_questions = pak->header.n_questions;
    uint16_t n_answers = pak->header.n_answers;
    uint16_t n_auth = pak->header.n_authorities;
    uint16_t n_additionals = pak->header.n_additionals;

    if (n_questions) {
        pak->questions = malloc(sizeof(dns_question_t) * n_questions);
        for (size_t j = 0; j < n_questions; ++j) {
            dns_question_init(pak->questions + j);
            dns_question_decode(pak->questions + j, buff, buff_l, &i);
        }
    }

    if (n_answers) {
        pak->answers = malloc(sizeof(dns_record_t) * n_answers);
        for (size_t j = 0; j < n_answers; ++j) {
            dns_record_init(pak->answers + j);
            dns_record_decode(pak->answers + j, buff, buff_l, &i);
        }
    }

    if (n_auth) {
        pak->authorities = malloc(sizeof(dns_record_t) * n_auth);
        for (size_t j = 0; j < n_auth; ++j) {
            dns_record_init(pak->authorities + j);
            dns_record_decode(pak->authorities + j, buff, buff_l, &i);
        }
    }

    if (n_additionals) {
        pak->additionals = malloc(sizeof(dns_record_t) * n_additionals);
        for (size_t j = 0; j < n_additionals; ++j) {
            dns_record_init(pak->additionals + j);
            dns_record_decode(pak->additionals + j, buff, buff_l, &i);
        }
    }

    return pak;
}

void dns_packet_dealloc(dns_packet_t *pak) {
    uint16_t n_questions = pak->header.n_questions;
    uint16_t n_answers = pak->header.n_answers;
    uint16_t n_auth = pak->header.n_authorities;
    uint16_t n_additionals = pak->header.n_additionals;

    dns_header_destroy(&pak->header);

    if (pak->questions) {
        for (size_t i = 0; i < n_questions; ++i) {
            dns_question_destroy(pak->questions + i);
        }
        free(pak->questions);
        pak->questions = NULL;
    }

    if (pak->answers) {
        for (size_t i = 0; i < n_answers; ++i) {
            dns_record_destroy(pak->answers + i);
        }
        free(pak->answers);
        pak->answers = NULL;
    }

    if (pak->authorities) {
        for (size_t i = 0; i < n_auth; ++i) {
            dns_record_destroy(pak->authorities + i);
        }
        free(pak->authorities);
        pak->authorities = NULL;
    }

    if (pak->additionals) {
        for (size_t i = 0; i < n_additionals; ++i) {
            dns_record_destroy(pak->additionals + i);
        }
        free(pak->additionals);
        pak->additionals = NULL;
    }
}

uint8_t *dns_query_encode(dns_header_t *header, dns_question_t *question, size_t *len) {
    // Length of the header, the message (and it's padding) and the rest of the message content
    size_t required_size = sizeof(dns_header_t) + 1 + strlen((char *) question->message) + 2 * sizeof(uint16_t);
    *len = required_size;

    uint8_t *buff = malloc(required_size);

    dns_header_encode(header, buff);

    if (!dns_question_encode(question, buff + sizeof(dns_header_t))) {
        printf("Failed to encode the DNS quesiton");
        exit(1);
    }

    return buff;
}

dns_packet_t *dns_send_query(struct in_addr server_addr, dns_header_t *header, dns_question_t *question) {
    size_t data_l = 0;
    uint8_t *data = dns_query_encode(header, question, &data_l);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        error("[EXE] Failed to create a socket. Cannot proceed.")
    }

    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0) {
        printf("Failed to set a proper timeout");
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr = server_addr;

    errno = 0;
    if (-1 == sendto(fd, data, data_l, 0, (struct sockaddr *) &addr, sizeof(addr))) {
        error("Failed to send the data to the DNS server (nothing sent). Cannot proceed.")
    } else if (errno) {
        error("Failed to send the data to the DNS server (error sending). Cannot proceed.")
    }
    free(data);

    // Receive the response
    socklen_t len = 0;
    size_t response_max_len = 1024;
    uint8_t *response = malloc(response_max_len);
    memset(response, 0xFC, response_max_len);

    errno = 0;
    size_t actual_length = recvfrom(fd, response, response_max_len, 0, (struct sockaddr *) &addr, &len);

    if (EAGAIN == errno || EWOULDBLOCK == errno) {
        printf("Sock timeout.\n");
        errno = 0;
        return NULL;
    } else if (errno) {
        error("Failed to read response. Cannot proceed.")
    }

    dns_packet_t *packet = dns_packet_create(response, actual_length);
    free(response);

    if (packet->header.id != header->id) {
        error("The response ID does not match the query ID!")
    }

    return packet;
}

dns_packet_t *dns_query(struct in_addr server_addr, char *domain, uint16_t type, uint16_t flags) {
    dns_header_t header = dns_header_init();

    header.id = rand() & 0xFFFF;
    header.flags |= flags;
    header.n_questions = 1;

    dns_question_t question;
    dns_question_init(&question);

    question.message = dns_name_encode(domain);
    question.class = CLASS_IN;
    question.type = type;

    dns_packet_t *packet = dns_send_query(server_addr, &header, &question);

    dns_header_destroy(&header);
    dns_question_destroy(&question);

    return packet;
}

/**
 * Print an IP from a byte array. Assumes at least 4 bytes.
 *
 * @param bytes
 */
void ip_print(uint8_t *bytes) {
    for (size_t k = 0; k < 4; ++k) {
        printf("%d", bytes[k]);
        if (k + 1 < 4) {
            printf(".");
        }
    }
}

struct in_addr dns_resolve_recursive(struct in_addr resolver, char *domain, uint16_t type, uint8_t max_recur_depth) {
    struct in_addr domain_addr;
    domain_addr.s_addr = 0;

    // return a blank addr
    if (!max_recur_depth) {
        return domain_addr;
    }


#ifdef VERBOSE
    printf("Querying ");
    ip_print((uint8_t *) &resolver.s_addr);
    printf(" for %s", domain);
    printf("\n");
#endif

    dns_packet_t *packet = dns_query(resolver, domain, type, FLAGS_RECUR);
    if (!packet) {
        return domain_addr;
    }

    for (uint16_t i = 0; i < packet->header.n_answers; ++i) {
        // take the first that defines an IP
        if (packet->answers[i].type == TYPE_A) {
            domain_addr.s_addr = *((uint32_t *) packet->answers[i].bytes);
            goto found;
        }
    }

    // Here, we have no answers. Let's check if any authorities are found
    // and find the authorities' IP within the additional. It may not be present!
    for (uint16_t auth_idx = 0; auth_idx < packet->header.n_authorities; ++auth_idx) {
        dns_record_t auth = packet->authorities[auth_idx];
        if (auth.type != TYPE_NS) continue;

        struct in_addr auth_addr;
        auth_addr.s_addr = 0;

        for (uint16_t add_idx = 0; add_idx < packet->header.n_additionals; ++add_idx) {
            dns_record_t additional = packet->additionals[add_idx];

            if (additional.type != TYPE_A && additional.class != CLASS_IN) continue;
            if (additional.data_len != 4) continue;
            if (0 != strcmp(additional.name, (char *) auth.bytes)) continue;

            auth_addr.s_addr = *((uint32_t *) additional.bytes);
            break;
        }

        if (auth_addr.s_addr != 0) {
            // Repeat the query to you
            domain_addr = dns_resolve_recursive(auth_addr, domain, type, max_recur_depth - 1);
            if (!domain_addr.s_addr) continue;

            goto found;
        } else {
            // type is NS so name is empty but bytes contains the ns' name
            struct in_addr other_resolver = dns_resolve_recursive(DEFAULT_RESOLVER, (char *) auth.bytes, TYPE_A,
                                                                  max_recur_depth - 1);
            if (!other_resolver.s_addr) continue;

            domain_addr = dns_resolve_recursive(other_resolver, domain, TYPE_A, max_recur_depth - 1);
            if (!domain_addr.s_addr) continue;

            goto found;
        }
    }

    printf("Failed to resolve domain '%s' on resolver ", domain);
    ip_print((uint8_t *) &resolver);
    printf(".\n");

    domain_addr.s_addr = 0;

    found:
#ifdef VERBOSE
    printf("%s <== ", domain);
    ip_print((uint8_t *) &domain_addr.s_addr);
    printf("\n");
#endif

    dns_packet_dealloc(packet);
    free(packet);

    return domain_addr;

}

struct in_addr dns_resolve(struct in_addr resolver, char *domain, uint16_t type) {
    return dns_resolve_recursive(resolver, domain, type, DNS_MAX_QUERY_DEPTH);
}

int main(int argc, char **argv) {
    if (!argc) {
        printf("Usage: domain");
    } else {
        char *domain_arg = argv[1];
        struct in_addr result = dns_resolve(DEFAULT_RESOLVER, domain_arg, TYPE_A);

        if (result.s_addr) {
            printf("Query for '%s': ", domain_arg);
            ip_print((uint8_t *) &result.s_addr);
        } else {
            printf("Failed to resolve domain %s.", domain_arg);
        }
    }


    return 0;
}
