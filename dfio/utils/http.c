#include "http_parser.h"

uint32_t http_parser_flags(const http_parser* parser)
{
	return parser->status_code | (parser->method<<16) | (parser->http_errno << 24) | (parser->upgrade << 31);
}