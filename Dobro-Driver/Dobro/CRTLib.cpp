#include <ntddk.h>
#include "CRTLib.h"

#pragma warning( push )
#pragma warning( disable : 4706 )

wchar_t* crt_wcscpy(wchar_t* d, const wchar_t* s)
{
    wchar_t* a = d;
    while ((*d++ = *s++));
    return a;
}

size_t crt_wcslen(const wchar_t* s)
{
    const wchar_t* a;
    for (a = s; *s; s++);
    return s - a;
}

wchar_t* crt_wcschr(const wchar_t* s, wchar_t c)
{
    if (!c) return (wchar_t*)s + crt_wcslen(s);
    for (; *s && *s != c; s++);
    return *s ? (wchar_t*)s : 0;
}

wchar_t* crt_wcsrchr(const wchar_t* wcs, const wchar_t wc)
{
  const wchar_t* retval = NULL;
  do
    if (*wcs == wc)
      retval = wcs;
  while (*wcs++ != L'\0');
  return (wchar_t*)retval;
}

size_t crt_wcscspn(const wchar_t* s, const wchar_t* c)
{
    const wchar_t* a;
    if (!c[0]) return crt_wcslen(s);
    if (!c[1]) return (s = crt_wcschr(a = s, *c)) ? s - a : crt_wcslen(a);
    for (a = s; *s && !crt_wcschr(c, *s); s++);
    return s - a;
}

size_t crt_wcsspn(const wchar_t* s, const wchar_t* c)
{
    const wchar_t* a;
    for (a = s; *s && crt_wcschr(c, *s); s++);
    return s - a;
}

wchar_t* crt_wcstok(wchar_t* s, const wchar_t* sep, wchar_t** p)
{
    if (!s && !(s = *p)) return NULL;
    s += crt_wcsspn(s, sep);
    if (!*s) return *p = 0;
    *p = s + crt_wcscspn(s, sep);
    if (**p) *(*p)++ = 0;
    else *p = 0;
    return s;
}

wchar_t* crt_wcsstr(const wchar_t* haystack, const wchar_t* needle)
{
  wchar_t b, c;
  if ((b = *needle) != L'\0')
  {
    haystack--;                                /* possible ANSI violation */
    do
      if ((c = *++haystack) == L'\0')
        goto ret0;
    while (c != b);
    if (!(c = *++needle))
      goto foundneedle;
    ++needle;
    goto jin;
    for (;;)
    {
      wchar_t a;
      const wchar_t* rhaystack, * rneedle;
      do
      {
        if (!(a = *++haystack))
          goto ret0;
        if (a == b)
          break;
        if ((a = *++haystack) == L'\0')
          goto ret0;
      shloop:;
      } while (a != b);
    jin:          if (!(a = *++haystack))
      goto ret0;
    if (a != c)
      goto shloop;
    if (*(rhaystack = haystack-- + 1) == (a = *(rneedle = needle)))
      do
      {
        if (a == L'\0')
          goto foundneedle;
        if (*++rhaystack != (a = *++needle))
          break;
        if (a == L'\0')
          goto foundneedle;
      } while (*++rhaystack == (a = *++needle));
      needle = rneedle;                  /* took the register-poor approach */
      if (a == L'\0')
        break;
    }
  }
foundneedle:
  return (wchar_t*)haystack;
ret0:
  return NULL;
}

wchar_t* crt_wcstristr(const wchar_t* haystack, const wchar_t* needle)
{
  wchar_t* pptr = (wchar_t*)needle;     /* Pattern to search for    */
  wchar_t* start = (wchar_t*)haystack;  /* Start with a bowl of hay */
  wchar_t* sptr;                        /* Substring pointer        */
  size_t   slen = crt_wcslen(haystack);    /* Total size of haystack   */
  size_t   plen = crt_wcslen(needle);      /* Length of our needle     */

  // Check if EMPTY
  if (!needle || !plen)
    return NULL;

  /* while string length not shorter than pattern length */
  for (; slen >= plen; start++, slen--)
  {
    /* find start of pattern in string */
    while (RtlUpcaseUnicodeChar(*start) != RtlUpcaseUnicodeChar(*needle))
    {
      start++;
      slen--;
      /* if pattern longer than string */
      if (slen < plen)
      {
        return NULL;
      }
    }

    sptr = start;
    pptr = (wchar_t*)needle;
    while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*pptr))
    {
      sptr++;
      pptr++;

      /* if end of pattern then pattern was found */
      if (L'\0' == *pptr)
      {
        return start;
      }
    }
  }

  return NULL;
}

#pragma warning( pop )
