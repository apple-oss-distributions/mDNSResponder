#include <stdio.h>
#include <stdarg.h>							// For va_list support

#include "mDNSsprintf.h"
#include "mDNSvsprintf.h"

static const struct mDNSsprintf_format
	{
	unsigned 		leftJustify : 1;
	unsigned 		forceSign : 1;
	unsigned 		zeroPad : 1;
	unsigned 		havePrecision : 1;
	unsigned 		hSize : 1;
	unsigned 		lSize : 1;
	char	 		altForm;
	char			sign;		// +, - or space
	int				fieldWidth;
	int				precision;
	} default_format = { 0 };

#define BUFLEN			512

int mDNS_vsprintf(char *sbuffer, const char *fmt, va_list arg)
	{
	int c, nwritten = 0;

	for (c = *fmt; c; c = *++fmt)
		{
		int i=0, j;
		char buf[BUFLEN], *digits;
		char *s = &buf[BUFLEN];
		struct mDNSsprintf_format F;
		if (c != '%') goto copy1;
		F = default_format;

		for (;;)	//  decode flags
			{
			c = *++fmt;
			if      (c == '-')	F.leftJustify = 1;
			else if (c == '+')	F.forceSign = 1;
			else if (c == ' ')	F.sign = ' ';
			else if (c == '#')	F.altForm++;
			else if (c == '0')	F.zeroPad = 1;
			else break;
			}

		if (c == '*')	//  decode field width
			{
			if ((F.fieldWidth = va_arg(arg, int)) < 0)
				{
				F.leftJustify = 1;
				F.fieldWidth = -F.fieldWidth;
				}
			c = *++fmt;
			}
		else
			{
			for (; c >= '0' && c <= '9'; c = *++fmt)
				F.fieldWidth = (10 * F.fieldWidth) + (c - '0');
			}

		if (c == '.')	//  decode precision
			{
			if ((c = *++fmt) == '*')
				{ F.precision = va_arg(arg, int); c = *++fmt; }
			else for (; c >= '0' && c <= '9'; c = *++fmt)
					F.precision = (10 * F.precision) + (c - '0');
			if (F.precision >= 0) F.havePrecision = 1;
			}

		if (F.leftJustify) F.zeroPad = 0;

conv:	switch (c)	//  perform appropriate conversion
			{
			unsigned long n;
			case 'h' :	F.hSize = 1; c = *++fmt; goto conv;
			case 'l' :	// fall through
			case 'L' :	F.lSize = 1; c = *++fmt; goto conv;
			case 'd' :
			case 'i' :	if (F.lSize) n = (unsigned long)va_arg(arg, long);
						else n = (unsigned long)va_arg(arg, int);
						if (F.hSize) n = (short) n;
						if ((long) n < 0) { n = (unsigned long)-(long)n; F.sign = '-'; }
						else if (F.forceSign) F.sign = '+';
						goto decimal;
			case 'u' :	if (F.lSize) n = va_arg(arg, unsigned long);
						else n = va_arg(arg, unsigned int);
						if (F.hSize) n = (unsigned short) n;
						F.sign = 0;
						goto decimal;
			decimal:	if (!F.havePrecision)
							{
							if (F.zeroPad)
								{
								F.precision = F.fieldWidth;
								if (F.sign) --F.precision;
								}
							if (F.precision < 1) F.precision = 1;
							}
						for (i = 0; n; n /= 10, i++) *--s = (char)(n % 10 + '0');
						for (; i < F.precision; i++) *--s = '0';
						if (F.sign) { *--s = F.sign; i++; }
						break;

			case 'o' :	if (F.lSize) n = va_arg(arg, unsigned long);
						else n = va_arg(arg, unsigned int);
						if (F.hSize) n = (unsigned short) n;
						if (!F.havePrecision)
							{
							if (F.zeroPad) F.precision = F.fieldWidth;
							if (F.precision < 1) F.precision = 1;
							}
						for (i = 0; n; n /= 8, i++) *--s = (char)(n % 8 + '0');
						if (F.altForm && i && *s != '0') { *--s = '0'; i++; }
						for (; i < F.precision; i++) *--s = '0';
						break;

			case 'a' :	{
						unsigned char *a = va_arg(arg, unsigned char *);
						unsigned short *w = (unsigned short *)a;
						s = buf;
						switch (F.precision)
							{
							case  4: i = mDNS_sprintf(s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]); break;
							case  6: i = mDNS_sprintf(s, "%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5]); break;
							case 16: i = mDNS_sprintf(s, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
												w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]); break;
							default: i = mDNS_sprintf(s, "%s", "ERROR: Must specify address size "
												"(i.e. %.4a=IPv4, %.6a=Ethernet, %.16a=IPv6) >>"); break;
							}
						}
						break;

			case 'p' :	F.havePrecision = F.lSize = 1;
						F.precision = 8;
			case 'X' :	digits = "0123456789ABCDEF";
						goto hexadecimal;
			case 'x' :	digits = "0123456789abcdef";
			hexadecimal:if (F.lSize) n = va_arg(arg, unsigned long);
						else n = va_arg(arg, unsigned int);
						if (F.hSize) n = (unsigned short) n;
						if (!F.havePrecision)
							{
							if (F.zeroPad)
								{
								F.precision = F.fieldWidth;
								if (F.altForm) F.precision -= 2;
								}
							if (F.precision < 1) F.precision = 1;
							}
						for (i = 0; n; n /= 16, i++) *--s = digits[n % 16];
						for (; i < F.precision; i++) *--s = '0';
						if (F.altForm) { *--s = (char)c; *--s = '0'; i += 2; }
						break;

			case 'c' :	*--s = (char)va_arg(arg, int); i = 1; break;

			case 's' :	s = va_arg(arg, char *);
						switch (F.altForm)
							{
							case 0: { char *a=s; i=0; while(*a++) i++; break; }	// C string
							case 1: i = (unsigned char) *s++; break;	// Pascal string
							case 2: {									// DNS label-sequence name
									unsigned char *a = (unsigned char *)s;
									s = buf;
									if (*a == 0) *s++ = '.';	// Special case for root DNS name
									while (*a && s + *a + 1 < &buf[BUFLEN])
										{
										s += mDNS_sprintf(s, "%#s.", a);
										a += 1 + *a;
										}
									i = (int)(s - buf);
									s = buf;
									break;
									}
							}
						if (F.havePrecision && i > F.precision) i = F.precision;
						break;

			case 'n' :	s = va_arg(arg, char *);
						if      (F.hSize) * (short *) s = (short)nwritten;
						else if (F.lSize) * (long  *) s = (long)nwritten;
						else              * (int   *) s = (int)nwritten;
						continue;

				//  oops - unknown conversion, abort

			case 'M': case 'N': case 'O': case 'P': case 'Q':
			case 'R': case 'S': case 'T': case 'U': case 'V':
			// (extra cases force this to be an indexed switch)
			default: goto done;

			case '%' :
			copy1    :	*sbuffer++ = (char)c; ++nwritten; continue;
			}

			//  pad on the left

		if (i < F.fieldWidth && !F.leftJustify)
			do { *sbuffer++ = ' '; ++nwritten; } while (i < --F.fieldWidth);

			//  write the converted result

		for (j=0; j<i; j++) *sbuffer++ = *s++;
		nwritten += i;

			//  pad on the right

		for (; i < F.fieldWidth; i++)
			{ *sbuffer++ = ' '; ++nwritten; }
		}

done: return(nwritten);
	}

int mDNS_sprintf(char *sbuffer, const char *fmt, ...)
{
	int	length;
	
    va_list ptr;
	va_start(ptr,fmt);
	length = mDNS_vsprintf(sbuffer, fmt, ptr);
	sbuffer[length] = 0;
	va_end(ptr);
	
	return length;
}
