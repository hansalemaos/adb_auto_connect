#define _CRT_SECURE_NO_WARNINGS
#include "ctre.hpp"
#include <iostream>
#ifdef _WIN32
#include <windows.h>

#define EXEC_CMD(command, mode) _popen(command, mode)
#define CLOSE_CMD(pipe) _pclose(pipe)
#else
#include <unistd.h>
#define EXEC_CMD(command, mode) popen(command, mode)
#define CLOSE_CMD(pipe) pclose(pipe)
#endif
#include "argparser.hpp"
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

static const char *On_IBlue{"\033[0;104m"};  // Blue
static const char *On_ICyan{"\033[0;106m"};  // Cyan
static const char *On_IGreen{"\033[0;102m"}; // Green
static const char *On_IRed{"\033[0;101m"};   // Red
static const char *Color_Off{"\033[0m"};     // Text Reset
static const char *IYellow{"\033[0;93m"};    // Yellow

static constexpr std::string_view explanation_on_how_to_use_this_app = R"(
                                                                                                                                        
Command-Line Arguments:
-----------------------
--adb_path:
    Specifies the path to the ADB executable.  
    Default:  --adb_path=adb
    
--min_port:
    Sets the minimum port number to consider when scanning for connections. Ports below this value will be ignored.  
    Default:  --min_port=5550

--limit_port:
    When set to a non-zero value, enables port limiting by configuring an environment variable for ADB.  
    Default:  --limit_port=1

--print_output:
    Controls verbosity. A non-zero value enables detailed log messages and colored output.  
    Default:  --print_output=0

--sleep_after_connect:
    Sets the delay (in milliseconds) after initiating connection commands, allowing time for processing.  
    Default:  --sleep_after_connect=2000

--sleep_after_loop:
    Specifies the delay (in milliseconds) after completing one full cycle of scanning and connecting before restarting the loop.  
    Default:  --sleep_after_loop=1000

--help=1:
    Displays this help message and exits.
                                                                                                                                        )";
static bool isspace_or_empty(std::string &str)
{
    if (str.size() == 0)
    {
        return true;
    }
    for (size_t i{}; i < str.size(); i++)
    {
        if (!::isspace(str[i]))
        {
            return false;
        }
    }
    return true;
}

static void _print_color(std::string &msg, const char *color)
{
    if (isspace_or_empty(msg))
    {
        return;
    }

    fputs(color, stdout);
    fputs(msg.c_str(), stdout);
    fputs(Color_Off, stdout);
    fputc('\n', stdout);
}
static void print_red_error(std::string &&msg)
{
    if (isspace_or_empty(msg))
    {
        return;
    }
    fputs(On_IRed, stderr);
    fputs(msg.c_str(), stderr);
    fputs(Color_Off, stderr);
    fputc('\n', stderr);
}
static void print_red(std::string &&msg)
{
    _print_color(msg, On_IRed);
}
static void print_yellow(std::string &&msg)
{
    _print_color(msg, IYellow);
}

static void print_blue(std::string &&msg)
{
    _print_color(msg, On_IBlue);
}

static void print_cyan(std::string &&msg)
{
    _print_color(msg, On_ICyan);
}

static void print_green(std::string &&msg)
{
    _print_color(msg, On_IGreen);
}

void sleepcp(int milliseconds)
{
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif // _WIN32
}

void static execute_cmd(std::string &cmd, std::string &output)
{
    output.clear();
    FILE *pipe{EXEC_CMD(cmd.c_str(), "r")};
    if (!pipe)
    {
        return;
    }
    static constexpr size_t buffer_size{128};
    char buffer[buffer_size];
    while (NULL != fgets(buffer, buffer_size, pipe))
    {
        output.append(buffer);
        std::memset(buffer, 0, buffer_size);
    }
    CLOSE_CMD(pipe);
}

static std::string ws2s(std::wstring &str)
{
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &str[0], (int)str.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

static std::wstring s2ws(std::string &str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

static int open_process_invisible(std::string &shell_command)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::wstring mycmd{s2ws(shell_command)};
    TCHAR mychararray[128]{};
    for (int i{}; i < mycmd.size(); i++)
    {
        mychararray[i] = mycmd.c_str()[i];
    }

    if (!CreateProcess(NULL,             // No module name (use command line)
                       mychararray,      // Command line ,   // Command line
                       NULL,             // Process handle not inheritable
                       NULL,             // Thread handle not inheritable
                       FALSE,            // Set handle inheritance to FALSE
                       CREATE_NO_WINDOW, // creation flags
                       NULL,             // Use parent's environment block
                       NULL,             // Use parent's starting directory
                       &si,              // Pointer to STARTUPINFO structure
                       &pi)              // Pointer to PROCESS_INFORMATION structure
    )
    {
        print_red_error("CreateProcess failed (" + std::to_string(GetLastError()) + ").\n");
        return -1;
    }
    int result{(int)pi.dwProcessId};
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
}

std::string static extract_first_ip_address(const std::string_view s) noexcept
{
    auto match = ctre::search<
        R"((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]):(?:[0-9]{1,5}))">(
        s);
    if (match)

    {
        return match.get<0>().to_string();
    }
    else
    {
        return "";
    }
}

void constexpr static lstrip_spaces_inplace(std::string &s)
{
    if (s.size() == 0)
    {
        return;
    }
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

void constexpr static rstrip_spaces_inplace(std::string &s)
{
    if (s.size() == 0)
    {
        return;
    }
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}
void constexpr static strip_spaces_inplace(std::string &s)
{
    if (s.size() == 0)
    {
        return;
    }
    lstrip_spaces_inplace(s);
    rstrip_spaces_inplace(s);
}

std::string get_short_path(std::string &file_path)
{
    auto longPath{s2ws(file_path)};
    DWORD bufferSize = GetShortPathNameW(longPath.c_str(), nullptr, 0);
    if (bufferSize == 0)
    {
        print_red_error("Error getting short path name.");
        return file_path;
    }

    std::wstring shortPath(bufferSize, L'\0');

    DWORD result = GetShortPathNameW(longPath.c_str(), &shortPath[0], bufferSize);
    if (result == 0)
    {
        print_red_error("Error getting short path name.");
        return file_path;
    }

    // Remove any extra null characters that may be present
    shortPath.resize(result);

    return ws2s(shortPath);
}

static std::string get_full_path(std::string &file_path)
{
    std::filesystem::path filePath(file_path);

    if (std::filesystem::exists(filePath))
    {
        return filePath.string();
    }
    else
    {
        std::string output_string;
        output_string.reserve(1024);
        std::string cmd2execute{"where " + file_path};
        execute_cmd(cmd2execute, output_string);
        strip_spaces_inplace(output_string);
        return output_string;
    }
}

static std::string get_pure_executable_name(std::string &file_path)
{
    std::filesystem::path filePath(file_path);
    return filePath.filename().string();
}

void static throw_error(const std::string &msg, int exit_code)
{
    std::cerr << On_IRed << msg << Color_Off << '\n';
    std::cerr << IYellow << explanation_on_how_to_use_this_app << Color_Off << '\n';
    exit(exit_code);
}

void static check_if_not_bad_value(const auto v, const auto bad_value, const std::string &error_message)
{
    if (v == bad_value)
    {
        throw_error(error_message, 1);
    }
}

typedef struct parsed_args
{
    std::string this_file;
    std::string adb_path;
    int min_port;
    int limit_port;
    int print_output;
    int sleep_after_connect;
    int sleep_after_loop;
    bool _adb_path;
    bool _min_port;
    bool _limit_port;
    bool _sleep_after_connect;
    bool _sleep_after_loop;
    bool _print_output;

} p_args;

auto static parse_args(int argc, char *argv[])
{
    parsed_args myargs{};
    auto parsed_args_vec{arghelpers::parse_args_to_string_vector(argc, argv)};
    for (auto const &[key, value] : parsed_args_vec)
    {

        if (arghelpers::compare2strings(key, "__FILE__"))
        {
            myargs.this_file = value;
        }
        else if (arghelpers::compare2strings(key, "help"))
        {
            print_red_error(std::string{explanation_on_how_to_use_this_app});
            exit(EXIT_FAILURE);
        }
        else if (arghelpers::compare2strings(key, "adb_path"))
        {
            myargs.adb_path = value;
            myargs._adb_path = true;
        }
        else if (arghelpers::compare2strings(key, "min_port"))
        {
            auto min_port{arghelpers::convert_to_int_at_any_cost(value, arghelpers::MAX_64BIT_INT)};
            check_if_not_bad_value(min_port, arghelpers::MAX_64BIT_INT, "Invalid min_port");
            if ((min_port > 65535) || (min_port < 0))
            {
                check_if_not_bad_value(arghelpers::MAX_64BIT_INT, arghelpers::MAX_64BIT_INT, "Invalid min_port");
            }

            myargs.min_port = (int)(min_port);
            myargs._min_port = true;
        }
        else if (arghelpers::compare2strings(key, "limit_port"))
        {
            auto limit_port{arghelpers::convert_to_int_at_any_cost(value, arghelpers::MAX_64BIT_INT)};
            check_if_not_bad_value(limit_port, arghelpers::MAX_64BIT_INT, "Invalid limit_port");
            if (limit_port > 0)
            {
                myargs.limit_port = 1;
                myargs._limit_port = true;
            }
            else
            {
                myargs.limit_port = 0;
                myargs._limit_port = false;
            }
        }
        else if (arghelpers::compare2strings(key, "print_output"))
        {
            auto print_output{arghelpers::convert_to_int_at_any_cost(value, arghelpers::MAX_64BIT_INT)};
            check_if_not_bad_value(print_output, arghelpers::MAX_64BIT_INT, "Invalid print_output");
            if (print_output > 0)
            {
                myargs.print_output = 1;
                myargs._print_output = true;
            }
            else
            {
                myargs.print_output = 0;
                myargs._print_output = false;
            }
        }
        else if (arghelpers::compare2strings(key, "sleep_after_connect"))
        {
            auto sleep_after_connect{arghelpers::convert_to_int_at_any_cost(value, arghelpers::MAX_64BIT_INT)};
            check_if_not_bad_value(sleep_after_connect, arghelpers::MAX_64BIT_INT, "Invalid sleep_after_connect");
            myargs.min_port = (int)(sleep_after_connect);
            myargs._min_port = true;
        }
        else if (arghelpers::compare2strings(key, "sleep_after_loop"))
        {
            auto sleep_after_loop{arghelpers::convert_to_int_at_any_cost(value, arghelpers::MAX_64BIT_INT)};
            check_if_not_bad_value(sleep_after_loop, arghelpers::MAX_64BIT_INT, "Invalid sleep_after_loop");
            myargs.min_port = (int)(sleep_after_loop);
            myargs._min_port = true;
        }
    }

    if (!myargs._adb_path)
    {
        myargs.adb_path = "adb";
    }
    if (!myargs._min_port)
    {
        myargs.min_port = 5550;
    }
    if (!myargs._sleep_after_connect)
    {
        myargs.sleep_after_connect = 2000;
    }
    if (!myargs._sleep_after_loop)
    {
        myargs.sleep_after_loop = 1000;
    }
    if (!myargs._limit_port)
    {
        myargs.limit_port = 1;
    }
    if (!myargs._print_output)
    {
        myargs.print_output = 0;
    }
    return myargs;
}

static constexpr std::string_view sv_listening{"LISTENING"};
static constexpr std::string_view sv_00000{"0.0.0.0"};
static constexpr std::string_view sv_127_0_0_1{"127.0.0.1"};
static constexpr std::string_view sv_offline{" offline "};
static constexpr std::array<int, 13> no_auto_connect{
    8080, 8000, 8888, 1433, 1521, 3306, 5000, 5432, 6379, 27017, 27018, 8443, 3389,
};
int main(int argc, char *argv[])
{
    parsed_args myargs{parse_args(argc, argv)};
    int min_port{myargs.min_port};
    bool print_output{(bool)myargs.print_output};
    int sleep_after_connect{myargs.sleep_after_connect};
    int sleep_after_loop{myargs.sleep_after_loop};
    std::string adb_path{myargs.adb_path};
    adb_path = get_full_path(adb_path);
    adb_path = get_short_path(adb_path);
    std::string adb_executable{get_pure_executable_name(adb_path)};
    std::string adb_disconnect{adb_path + " disconnect "};
    std::string start_adb_server{adb_path + " start-server"};
    std::string wm_mic_cmd{"wmic process where name=\"" + adb_executable + "\" get ProcessId,CommandLine"};
    std::string set_min_port{"Reg.exe add \"HKCU\\Environment\" /v \"ADB_LOCAL_TRANSPORT_MAX_PORT\" /t REG_SZ /d " +
                             std::to_string(min_port) + " /f"};
    if (myargs.limit_port)
    {
        system(set_min_port.c_str());
    }
    system(start_adb_server.c_str());
    std::string netstat_cmd{"netstat -a -b -n -o -p TCP"};
    std::string adb_devices_cmd{adb_path + " devices -l"};
    std::string netstat_output{};
    std::string adb_devices_output{};
    std::string wm_mic_output{};
    std::vector<std::string> found_ip_addresses{};
    std::vector<std::string> already_found_ip_addresses{};
    std::vector<std::string> pids_of_procs{};

    while (1)
    {
        try
        {
            system(start_adb_server.c_str());
            found_ip_addresses.clear();
            already_found_ip_addresses.clear();
            pids_of_procs.clear();
            execute_cmd(netstat_cmd, netstat_output);
            execute_cmd(adb_devices_cmd, adb_devices_output);
            auto strs{adb_devices_output | std::views::split('\n')};
            for (const auto &refr : strs)
            {
                std::string_view tmpview{refr.begin(), refr.end()};
                if (((tmpview.find(sv_127_0_0_1) != std::string_view::npos) ||
                     (tmpview.find(sv_00000) != std::string_view::npos)))
                {
                    std::string found_ip_address{extract_first_ip_address(tmpview)};
                    if (!found_ip_address.empty())
                    {
                        if (print_output)
                        {
                            print_yellow("Already connected: " + found_ip_address);
                        }
                        already_found_ip_addresses.emplace_back(found_ip_address);
                    }
                }
            }
            strs = netstat_output | std::views::split('\n');
            for (const auto &refr : strs)
            {
                std::string_view tmpview{refr.begin(), refr.end()};
                if ((tmpview.find(sv_listening) != std::string_view::npos) &&
                    ((tmpview.find(sv_127_0_0_1) != std::string_view::npos) ||
                     (tmpview.find(sv_00000) != std::string_view::npos)))
                {
                    std::string found_ip_address{extract_first_ip_address(tmpview)};
                    if (!found_ip_address.empty())
                    {
                        if (std::find(already_found_ip_addresses.begin(), already_found_ip_addresses.end(),
                                      found_ip_address) != already_found_ip_addresses.end())
                        {
                            if (print_output)
                            {
                                print_cyan("SKIPPING: " + found_ip_address);
                            }
                            continue;
                        }
                        std::string port{found_ip_address.substr(found_ip_address.find(':') + 1)};
                        int port_as_int{std::stoi(port)};
                        if (std::find(no_auto_connect.begin(), no_auto_connect.end(), port_as_int) !=
                            no_auto_connect.end())
                        {
                            continue;
                        }
                        if (port_as_int < min_port)
                        {
                            continue;
                        }
                        found_ip_addresses.emplace_back(adb_path + " connect " + found_ip_address);
                    }
                }
            }
            for (size_t j{}; j < found_ip_addresses.size(); j++)
            {
                if (print_output)
                {
                    print_green("Connecting to: " + found_ip_addresses[j]);
                }
                int mypid{open_process_invisible(found_ip_addresses[j])};
                if (mypid == -1)
                {
                    continue;
                }
                if (print_output)
                {
                    print_blue(std::string{"PID of process: " + std::to_string(mypid)});
                }
                pids_of_procs.emplace_back(" " + std::to_string(mypid));
            }
            sleepcp(sleep_after_connect);

            execute_cmd(wm_mic_cmd, wm_mic_output);
            auto strs2{wm_mic_output | std::views::split('\n')};
            for (const auto &refr : strs2)
            {
                std::string tmpstring{refr.begin(), refr.end()};
                strip_spaces_inplace(tmpstring);
                for (size_t j{}; j < pids_of_procs.size(); j++)
                {
                    if (tmpstring.find(pids_of_procs[j]) != std::string::npos)
                    {
                        if (print_output)
                        {
                            print_blue("Process is still running: " + pids_of_procs[j]);
                        }
                        std::string taskkill_cmd{"taskkill /F /PID" + pids_of_procs[j]};
                        open_process_invisible(taskkill_cmd);
                    }
                }
            }
            execute_cmd(adb_devices_cmd, adb_devices_output);
            auto strs3{adb_devices_output | std::views::split('\n')};
            for (const auto &refr : strs3)
            {
                std::string tmpstring{refr.begin(), refr.end()};
                if (tmpstring.find(sv_offline) == std::string::npos)
                {
                    continue;
                }
                auto first_space{tmpstring.find(' ')};
                if (first_space == std::string::npos)
                {
                    continue;
                }
                std::string adb_device{adb_disconnect + tmpstring.substr(0, first_space)};
                if (print_output)
                {
                    print_blue("Executing disconnect cmd: " + adb_device);
                }
                open_process_invisible(adb_device);
            }
        }
        catch (const std::exception &e)
        {
            print_red_error("Error: " + std::string{e.what()});
        }
        sleepcp(sleep_after_loop);
    }
}
