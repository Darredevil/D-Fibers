import std.stdio;
import std.net.curl;
import dfio;

void main()
{
    auto content = get("wttr.in");
    writeln(content);
}
