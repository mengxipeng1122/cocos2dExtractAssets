
#include <stdarg.h>
static void frida_log (const char * format, ...);
extern void _frida_log ( char * message);

const char* s = "go here asdfasdfasdfasdfasdfadfsadf";
void test (void)
{
    
//    _frida_log((char*)s);
}


static void
frida_log (const char * format,
           ...)
{
  va_list args;

  va_start (args, format);
  va_end (args);

//  _frida_log (message);

}
