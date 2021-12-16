#pragma once

wchar_t* crt_wcscpy(wchar_t* d, const wchar_t* s);
size_t crt_wcslen(const wchar_t* s);
wchar_t* crt_wcsch(const wchar_t* s, wchar_t c);
wchar_t* crt_wcsrchr(const wchar_t* wcs, const wchar_t wc);
size_t crt_wcsspn(const wchar_t* s, const wchar_t* c);
size_t crt_wcscspn(const wchar_t* s, const wchar_t* c);
wchar_t* crt_wcstok(wchar_t* s, const wchar_t* sep, wchar_t** p);
wchar_t* crt_wcsstr(const wchar_t* haystack, const wchar_t* needle);
wchar_t* crt_wcstristr(const wchar_t* haystack, const wchar_t* needle);
