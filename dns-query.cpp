#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>        // PRIu64 PRId64 PRIx64 PRIu32 PRId32 ...

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ARRAY_LEN(arr) (sizeof (arr) / sizeof ((arr)[0]))

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define DNS_MESSAGE_MAX_SIZE  512

#define DNS_RECORD_TYPE_A      1  // host address
#define DNS_RECORD_TYPE_NS     2  // authoritative name server
#define DNS_RECORD_TYPE_MX    15  // mail exchange
#define DNS_RECORD_TYPE_TXT   16  // test strings
#define DNS_RECORD_TYPE_AAAA  28  // IPv6 host address
#define DNS_RECORD_CLASS_IN    1  // internet


struct DnsHeader {
  u16 id;
  u8 flags[2];
  u16 questions_count;          // QDCOUNT
  u16 answers_count;            // ANCOUNT
  u16 nameservers_count;        // NSCOUNT
  u16 additionals_count;        // ARCOUNT
};


struct DnsQuestion {
  const char *name;
  u16 q_type;
  u16 q_class;
};


static void print_ipv6_addr_n (u8 *addr)
{
  u16 *p = (u16 *) addr;
  for (u16 i = 0; i < 7; i++)
    {
      if (p[i]) printf ("%x", ntohs (p[i]));
      printf (":");
    }

  printf ("%x", ntohs (p[7]));
}


static void print_dns_header (DnsHeader header)
{
  header.id = ntohs (header.id);

  u8 is_response          = (header.flags[0] >> 7);
  u8 opcode               = (header.flags[0] >> 3) & 0b1111;
  u8 authoritative        = (header.flags[0] >> 2) & 0b0001;
  u8 truncation           = (header.flags[0] >> 1) & 0b0001;
  u8 recursion_desired    = (header.flags[0]     ) & 0b0001;
  u8 recursion_available  = (header.flags[1] >> 7);
  u8 response_code        = (header.flags[1]     ) & 0b1111;

  header.questions_count   = ntohs (header.questions_count);
  header.answers_count     = ntohs (header.answers_count);
  header.nameservers_count = ntohs (header.nameservers_count);
  header.additionals_count = ntohs (header.additionals_count);
  printf ("    id: 0x%" PRIx16 "\n", header.id);
  printf ("    flags: 0x%02" PRIx8 "%02" PRIx8 "\n", header.flags[0], header.flags[1]);
  printf ("    QR:%d OPCODE:%d AA:%d TC:%d RD:%d RA:%d ",
          is_response,
          opcode,
          authoritative,
          truncation,
          recursion_desired,
          recursion_available);

  switch (response_code)
    {
    case 0: printf ("RCODE: 0 (OK)\n"); break;
    case 1: printf ("RCODE: 1 (Format Error)\n"); break;
    case 2: printf ("RCODE: 2 (Server Failure)\n"); break;
    case 3: printf ("RCODE: 3 (Name Error)\n"); break;
    case 4: printf ("RCODE: 4 (Not Implemented)\n"); break;
    case 5: printf ("RCODE: 5 (Refused)\n"); break;
    }

  printf ("    questions_count: %"   PRIu16 "\n", header.questions_count);
  printf ("    answers_count: %"     PRIu16 "\n", header.answers_count);
  printf ("    nameservers_count: %" PRIu16 "\n", header.nameservers_count);
  printf ("    additionals_count: %" PRIu16 "\n", header.additionals_count);
}


static u8 * print_dns_labels (u8 *data, u8 *data_p, u8 *data_end)
{
  while (data_p < data_end)
    {
      // printf ("p:%" PRIu16 " ", (u16) (data_p - data));
      u8 len = (data_p++)[0];
      // printf ("l:%" PRIu8 " ", len);
      if (len >= 64)
        {
          assert ((len & 0b11000000) == 0b11000000);
          assert (data_p < data_end);
          u16 offset = ((len & 0b00111111) << 8) | (data_p++)[0];
          print_dns_labels (data, data + offset, data_p - 2);
          break;
        }
      else if (len)
        {
          assert (data_p + len <= data_end);
          printf ("%.*s.", len, (char *) data_p);
          data_p += len;
        }
      else
        {
          break;
        }
    }

  return data_p;
}


static u8 * print_dns_question (u8 *data, u8 *data_p, u8 *data_end)
{
  printf ("    ");
  data_p = print_dns_labels (data, data_p, data_end);
  printf ("\t ");
  u8 *question_end = data_p + 4;
  assert (question_end <= data_end);

  u16 qtype = ntohs (((u16 *) data_p)[0]);
  data_p += 2;
  u16 qclass = ntohs (((u16 *) data_p)[0]);
  data_p += 2;

  switch (qtype)
    {
    case DNS_RECORD_TYPE_A:    printf ("A     "); break;
    case DNS_RECORD_TYPE_MX:   printf ("MX    "); break;
    case DNS_RECORD_TYPE_AAAA: printf ("AAAA  "); break;
    default: assert (!"Unknown question type");
    }
  switch (qclass)
    {
    case DNS_RECORD_CLASS_IN: printf ("IN\n"); break;
    default: assert (!"Unknown question class");
    }

  return data_p;
}


static u8 * print_dns_record (u8 *data, u8 *data_p, u8 *data_end)
{
  printf ("    ");
  data_p = print_dns_labels (data, data_p, data_end);
  printf ("\t ");
  assert (data_end - data_p >= 10);

  u16 rtype = ntohs (((u16 *) data_p)[0]);
  data_p += 2;
  u16 rclass = ntohs (((u16 *) data_p)[0]);
  data_p += 2;
  u32 ttl = ntohl (((u32 *) data_p)[0]);
  data_p += 4;
  assert (ttl);
  u16 resource_len = ntohs (((u16 *) data_p)[0]);
  data_p += 2;
  u8 *record_end = data_p + resource_len;
  assert (record_end <= data_end);

  switch (rtype)
    {
    case DNS_RECORD_TYPE_A:    printf ("A     "); break;
    case DNS_RECORD_TYPE_NS:   printf ("NS    "); break;
    case DNS_RECORD_TYPE_AAAA: printf ("AAAA  "); break;
    default:
      printf ("DNS_RECORD_TYPE: %" PRIu16 "\n", rtype);
      assert (!"Unknown record TYPE");
    }
  switch (rclass)
    {
    case DNS_RECORD_CLASS_IN:
      {
        printf ("IN  ");
      } break;
    default:
      {
        printf ("\n");
        assert (!"Unknown record CLASS");
      }
    }

  printf ("%6" PRIu32 "  ", ttl);

  if (rclass == DNS_RECORD_CLASS_IN)
    {
      switch (rtype)
        {
        case DNS_RECORD_TYPE_A:
          {
            assert (resource_len == 4);
            printf ("%u.%u.%u.%u\n", data_p[0], data_p[1], data_p[2], data_p[3]);
          } break;
        case DNS_RECORD_TYPE_NS:
          {
            u8 *p = print_dns_labels (data, data_p, record_end);
            printf ("\n");
            assert (p == record_end);
          } break;
        case DNS_RECORD_TYPE_AAAA:
          {
            assert (resource_len == 16);
            print_ipv6_addr_n (data_p);
            printf ("\n");
          } break;
        default:
          {
            printf ("DATA:");
            if (resource_len)
              {
                printf ("%02x", data_p[0]);
                for (u16 i = 1; i < resource_len; ++i)
                  {
                    printf (" %02x", data_p[i]);
                  }
              }
            printf ("\n");
          }
        }
      data_p += resource_len;
    }
  else
    {
      printf ("Unknown record class:%" PRIu16"\n", rclass);
      assert (0);
    }

  return data_p;
}


static void print_dns_message (u8 *data, u16 len)
{
  assert (len >= 12);

  u8 *data_p   = data;
  u8 *data_end = data + len;
  DnsHeader *header = (DnsHeader *) data_p;
  data_p += sizeof (DnsHeader);
  print_dns_header (header[0]);

  if (header->questions_count)
    {
      assert (data_p < data_end);
      u16 questions_count = ntohs (header->questions_count);
      printf ("questions:\n");
      while (questions_count--)
        {
          data_p = print_dns_question (data, data_p, data_end);
        }
    }

  if (header->answers_count)
    {
      assert (data_p < data_end);
      u16 answers_count = ntohs (header->answers_count);
      printf ("answers:\n");
      while (answers_count--)
        {
          data_p = print_dns_record (data, data_p, data_end);
        }
    }

  if (header->nameservers_count)
    {
      assert (data_p < data_end);
      u16 nameservers_count = ntohs (header->nameservers_count);
      printf ("nameservers:\n");
      while (nameservers_count--)
        {
          data_p = print_dns_record (data, data_p, data_end);
        }
    }

  if (header->additionals_count)
    {
      assert (data_p < data_end);
      u16 additionals_count = ntohs (header->additionals_count);
      printf ("additionals:\n");
      while (additionals_count--)
        {
          data_p = print_dns_record (data, data_p, data_end);
        }
    }

  assert (data_p == data_end);
}


static u16 make_dns_query (u8 *data, DnsQuestion questions[], u32 questions_count)
{
  u8 *data_p = data;
  u8 *data_end = data + DNS_MESSAGE_MAX_SIZE;

  DnsHeader *header = (DnsHeader *) data_p;
  header->id = htons (rand());
  header->flags[0] = 0b00000001;
  header->flags[1] = 0b00000000;
  header->questions_count = htons (questions_count);
  header->answers_count = 0;
  header->nameservers_count = 0;
  header->additionals_count = 0;
  data_p += sizeof (DnsHeader);

  for (u32 i = 0; i < questions_count; ++i)
    {
      DnsQuestion question = questions[i];
      const char *question_name = question.name;
      printf ("question_name: %s\n", question_name);
      u16 label_len = 0;
      while (question_name[label_len])
        {
          if (question_name[label_len] == '.')
            {
              assert (label_len < 64);
              assert (data_p < data_end);
              (data_p++)[0] = label_len;
              assert (data_p + label_len < data_end);
              for (; label_len; --label_len) (data_p++)[0] = (question_name++)[0];
              ++question_name;
            }
          else
            {
              ++label_len;
            }
        }
      assert (data_p < data_end);
      (data_p++)[0] = label_len;
      assert (data_p + label_len < data_end);
      for (; label_len; --label_len) (data_p++)[0] = (question_name++)[0];

      assert (data_p + 5 < data_end);
      (data_p++)[0] = 0;
      ((u16 *) data_p)[0] = htons (question.q_type);
      data_p += 2;
      ((u16 *) data_p)[0] = htons (question.q_class);
      data_p += 2;
    }


  return data_p - data;
}


int main (int argc, char *argv[])
{
  srand (time (0));

  char *server_name = NULL;
  DnsQuestion questions[16];
  u32 questions_count = 0;
  u32 questions_max = ARRAY_LEN (questions);
  u16 q_type = DNS_RECORD_TYPE_A;

  for (int i = 1; i < argc; ++i)
    {
      char *arg = argv[i];
      if (!strcmp (arg, "-dns"))
        {
          i++;
          assert (i < argc);
          server_name = argv[i];
        }
      else if (!strcmp (arg, "A"))    q_type = DNS_RECORD_TYPE_A;
      else if (!strcmp (arg, "NS"))   q_type = DNS_RECORD_TYPE_NS;
      else if (!strcmp (arg, "MX"))   q_type = DNS_RECORD_TYPE_MX;
      else if (!strcmp (arg, "TXT"))  q_type = DNS_RECORD_TYPE_TXT;
      else if (!strcmp (arg, "AAAA")) q_type = DNS_RECORD_TYPE_AAAA;
      else
        {
          assert (arg[0] != '-');
          assert (questions_count < questions_max);
          questions[questions_count++] = {argv[i], q_type, DNS_RECORD_CLASS_IN};
        }
    }

  if (!server_name)
    {
      server_name = (char *) "127.0.0.1";
    }

  if (!questions_count)
    {
      fprintf (stderr, "%s: Error: Must provide a domain name.\n", argv[0]);
      return 1;
    }

  u8 query_buffer[DNS_MESSAGE_MAX_SIZE];
  u16 query_len = make_dns_query (query_buffer, questions, questions_count);
  printf ("query[%" PRIu16 "]:\n", query_len);
  print_dns_message (query_buffer, query_len);

  sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons (53);
  int server_addr_is_valid = inet_aton (server_name, &server_addr.sin_addr);
  assert (server_addr_is_valid);

  int sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  assert (sockfd != -1);
  int connect_error = connect (sockfd, (sockaddr *) &server_addr, sizeof (server_addr));
  assert (!connect_error);

  write (sockfd, query_buffer, query_len);

  u8 response_buffer[DNS_MESSAGE_MAX_SIZE];
  ssize_t recvfrom_status = read (sockfd, response_buffer, sizeof (response_buffer));
  if (recvfrom_status < 0)
    {
      int error = errno;
      printf ("recvfrom: %s\n", strerror (error));
    }
  assert (recvfrom_status >= 0);
  assert (recvfrom_status);
  close (sockfd);

  u32 response_len = (u32) recvfrom_status;

  // int fd = creat ("out", 0777);
  // assert (fd != -1);
  // write (fd, response_buffer, response_len);
  // close (fd);

  printf ("\nresponse[%" PRIu16 "]:\n", response_len);
  print_dns_message (response_buffer, response_len);

  return 0;
}
