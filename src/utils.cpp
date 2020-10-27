/*
 * Various helper routines either written by me or found under open licenses on sites like Stack Overflow
 * and Stack Exchange.
 */

#include <memory>
#include <string>
#include <stdexcept>


/*
 * CC0 1.0 Licensed by Stack Overflow user iFreilicht
 */

template<typename ... Args>
std::string string_format( const std::string& format, Args ... args )
{
    size_t size = snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
    if( size <= 0 ){ throw std::runtime_error( "Error during formatting." ); }
    std::unique_ptr<char[]> buf( new char[ size ] ); 
    snprintf( buf.get(), size, format.c_str(), args ... );
    return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
}
