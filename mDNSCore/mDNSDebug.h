// Set DEBUGBREAKS to 0 to optimize debugf() calls out of the compiled code
// Set DEBUGBREAKS to 1 to generate normal debugging messages
// Set DEBUGBREAKS to 2 to generate verbose debugging messages
// DEBUGBREAKS is normally set in the project options (or makefile) but can also be set here if desired

//#define DEBUGBREAKS 2

#ifdef	__cplusplus
	extern "C" {
#endif

#if DEBUGBREAKS
#define debugf debugf_
extern void debugf_(const char *format, ...);
#else // If debug breaks are off, use a preprocessor trick to optimize those calls out of the code
	#if( defined( __GNUC__ ) )
		#define	debugf( ARGS... )
	#elif( defined( __MWERKS__ ) )
		#define	debugf( ... )
	#else
		#define debugf 1 ? ((void) 0) : (void)
	#endif
#endif

#if DEBUGBREAKS > 1
#define verbosedebugf debugf_
#else
	#if( defined( __GNUC__ ) )
		#define	verbosedebugf( ARGS... )
	#elif( defined( __MWERKS__ ) )
		#define	verbosedebugf( ... )
	#else
		#define verbosedebugf 1 ? ((void) 0) : (void)
	#endif
#endif

#ifdef	__cplusplus
	}
#endif
