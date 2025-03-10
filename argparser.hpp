#ifndef ARGPARSER_HPP
#define ARGPARSER_HPP
#include <algorithm>
#include <array>
#include <ranges>
#include <string>
#include <utility>
#include <variant>
#include <vector>
namespace arghelpers
{
static constexpr int64_t MAX_64BIT_INT = 9223372036854775807;
static constexpr double MAX_64BIT_INT_AS_DOUBLE = 9223372036854775807.0;
static constexpr std::string_view nan_string = "NotANumber";
static constexpr std::string_view integer_numbers_string_view = "0123456789";
static constexpr std::string_view float_numbers_string_view = "0123456789.";
static constexpr std::string_view hex_upper_letters_string_view = "0123456789ABCDEF";
static constexpr std::string_view hex_lower_letters_string_view = "0123456789abcdef";
static constexpr std::string_view prefix_0b = "0b";
static constexpr std::string_view prefix_01 = "01";
static constexpr std::string_view prefix_0x = "0x";
static constexpr std::string_view number_0 = "0";
static constexpr char integer_numbers[] = "0123456789";
static constexpr char float_numbers[] = "0123456789.";
static constexpr char hex_upper_letters[] = "0123456789ABCDEF";
static constexpr unsigned int FNV_PRIME = 16777619u;
static constexpr std::string_view bool1 = "True";
static constexpr std::string_view bool2 = "False";
static constexpr std::string_view bool3 = "true";
static constexpr std::string_view bool4 = "false";
static constexpr std::string_view bool5 = "0";
static constexpr std::string_view bool6 = "1";
static constexpr std::string_view bool7 = "TRUE";
static constexpr std::string_view bool8 = "FALSE";
static constexpr std::string_view emptystringview = "";
static constexpr std::string_view zero1 = "0";
static constexpr std::string_view zero2 = "0.0";
static constexpr std::string_view zero3 = ".0";
static constexpr std::string_view zero4 = "-0";
static constexpr std::string_view zero5 = "-0.0";
static constexpr std::string_view zero6 = "+0.0";
constexpr std::array<uint8_t, 256> array_ascii_replace_non_alphanumeric = {
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  32,  32,  32,  32,  32,  32,  32,  65,
    66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,
    88,  89,  90,  32,  32,  32,  32,  32,  32,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32};

constexpr std::array<uint8_t, 256> array_ascii_replace_non_printable = {
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,
    44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  65,
    66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,
    88,  89,  90,  91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32};
constexpr std::array<uint8_t, 256> array_ascii_replace_non_numeric = {
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 0-15
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 16-31
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 32-47
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57,                         // 48-57 (digits '0'-'9')
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 58-73
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 74-89
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 90-105
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 106-121
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 122-137
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 138-153
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 154-169
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 170-185
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 186-201
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 202-217
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 218-233
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32  // 234-255
};
constexpr std::array<uint8_t, 256> array_ascii_replace_non_numeric_float = {
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 0-15
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 16-31
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 46, 32, // 32-47
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57,                         // 48-57 (digits '0'-'9')
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 58-73
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 74-89
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 90-105
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 106-121
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 122-137
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 138-153
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 154-169
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 170-185
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 186-201
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 202-217
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 218-233
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32  // 234-255
};

constexpr std::array<uint8_t, 256> array_ascii_replace_non_numeric_float_with_comma = {
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 0-15
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 16-31
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 44, 32, 46, 32, // 32-47
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57,                         // 48-57 (digits '0'-'9')
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 58-73
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 74-89
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 90-105
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 106-121
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 122-137
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 138-153
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 154-169
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 170-185
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 186-201
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 202-217
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, // 218-233
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32  // 234-255
};

static constexpr bool to_bool(const std::string_view s)
{

    if (s == bool1 || s == bool3 || s == bool6 || s == bool7)
    {
        return true;
    }
    return false;
}
static bool is_int_number(const std::string_view s)
{

    if (s.size() == 0)
    {
        return false;
    };
    if ((s.size() > 1) && ((s[0] == '-') || (s[0] == '+')) && ((s[1] != '-') && (s[1] != '+')))
    {
        return is_int_number(s.substr(1, s.size() - 1));
    }
    for (const char &i : s)
    {
        bool isnumber = false;
        for (const char &j : integer_numbers)
        {
            if (i == j)
            {
                isnumber = true;
                break;
            }
        }
        if (!isnumber)
        {
            return false;
        }
    }
    return true;
}
static bool is_float_number(const std::string_view s)
{
    if (s.size() == 0)
    {
        return false;
    };
    if ((s.size() > 1) && ((s[0] == '-') || (s[0] == '+')) && ((s[1] != '-') && (s[1] != '+')))
    {
        return is_float_number(s.substr(1, s.size() - 1));
    }
    size_t dotcounter = 0;
    for (const char &i : s)
    {
        bool isnumber = false;
        for (const char &j : float_numbers)
        {
            if (i == j)
            {
                if (i == '.')
                {
                    dotcounter += 1;
                    if (dotcounter > 1)
                    {
                        return false;
                    }
                }
                isnumber = true;
                break;
            }
        }
        if (!isnumber)
        {
            return false;
        }
    }
    return true;
}
static std::variant<double, int64_t> to_float_or_int(std::string_view s)
{
    std::variant<double, int64_t> returnvalue{};
    std::string tmpstring = std::string(s);
    if (is_int_number(s))
    {
        returnvalue = std::stoll(tmpstring);
    }
    else if (is_float_number(s))
    {
        returnvalue = std::stod(tmpstring);
    }
    return returnvalue;
}
bool check_if_string_is_valid_float_zero(const std::string_view str)
{

    if (is_float_number(str))
    {
        if (atof(str.data()) == 0)
        {
            return true;
        }
    }
    size_t strlen = str.size();
    if ((strlen > 1) && (str[0] == '+') && (is_float_number(str.substr(1, strlen - 1))))
    {
        return ((atof(&str.data()[1])) == 0);
    }
    if ((strlen > 1) && (str[0] == '-') && (is_float_number(str.substr(1, strlen - 1))))
    {
        return ((atof(&str.data()[1])) == 0);
    }
    return false;
}

bool check_if_string_is_valid_int_zero(const std::string_view str)
{

    if ((str == zero1) || (str == zero2) || (str == zero3) || (str == zero4) || (str == zero5) || (str == zero6))
    {
        return true;
    }

    size_t strlen = str.size();

    if (strlen == 0)
    {
        return false;
    }
    if ((strlen > 1) && (str[0] == '+') && (is_float_number(str.substr(1, strlen - 1))))
    {
        return (int(atof(&str.data()[1])) == 0);
    }
    if ((strlen > 1) && (str[0] == '-') && (is_float_number(str.substr(1, strlen - 1))))
    {
        return ((atof(&str.data()[1])) == 0);
    }
    if (is_int_number(str))
    {
        return (int(atof(str.data())) == 0);
    }

    if ((str[0] != '0') && (str[0] != '.'))
    {
        return false;
    }
    if ((str[0] == '.') && (strlen == 1))
    {
        return false;
    }

    if (str[0] == '.')
    {
        return is_int_number(str.substr(1, strlen - 1));
    }
    if ((str[0] == '0') && (strlen == 1))
    {
        return true;
    }
    if (is_float_number(str))
    {
        double tempdouble = atof(str.data());
        return (tempdouble < 1) && (tempdouble >= 0);
    }
    return false;
}
int64_t convert_to_int_at_any_cost(const std::string_view _sv, int64_t nan_value)
{
    std::variant<double, int64_t> tmpvalue = to_float_or_int(_sv);
    int64_t tmpnumber;
    try
    {
        tmpnumber = std::get<int64_t>(tmpvalue);
    }
    catch (...)
    {
        try
        {
            tmpnumber = (int64_t)(std::get<double>(tmpvalue));
        }
        catch (...)
        {
            // do nothing
        }
    }

    if (tmpnumber != 0)
    {
        return tmpnumber;
    }
    if ((tmpnumber == 0) && (check_if_string_is_valid_int_zero(_sv)))
    {
        return 0;
    }

    return nan_value;
}
double convert_to_double_at_any_cost(const std::string_view _sv, double nan_value)
{
    std::variant<double, int64_t> tmpvalue = to_float_or_int(_sv);
    double tmpnumber;
    try
    {
        tmpnumber = std::get<double>(tmpvalue);
    }
    catch (...)
    {
        try
        {
            tmpnumber = (double)(std::get<int64_t>(tmpvalue));
        }
        catch (...)
        {
            // do nothing
        }
    }
    if (tmpnumber != 0)
    {
        return tmpnumber;
    }
    if ((tmpnumber == 0) && (check_if_string_is_valid_float_zero(_sv)))
    {
        return 0;
    }

    return nan_value;
}
static constexpr bool is_hex_notation_upper_with_0x(const std::string_view input)
{
    return input.compare(0, 2, prefix_0x) == 0 && input.size() > 2 &&
           (input.find_first_not_of(hex_upper_letters_string_view, 2) == std::string_view::npos);
}
static constexpr bool is_hex_notation_upper_without_0x(const std::string_view input)
{
    return input.size() > 0 && (input.find_first_not_of(hex_upper_letters_string_view, 2) == std::string_view::npos);
}
static constexpr bool is_hex_notation_lower_with_0x(const std::string_view input)
{
    return input.compare(0, 2, prefix_0x) == 0 && input.size() > 2 &&
           (input.find_first_not_of(hex_lower_letters_string_view, 2) == std::string_view::npos);
}
static constexpr bool is_hex_notation_lower_without_0x(const std::string_view input)
{
    return input.size() > 0 && (input.find_first_not_of(hex_lower_letters_string_view, 2) == std::string_view::npos);
}
static std::string normalize_whitespaces(const std::string_view &invecj)
{
    std::string outvecj;
    outvecj.reserve(invecj.size());
    int last_whitespace_counter = 1;
    for (size_t i = 0; i < invecj.size(); i++)
    {
        if ((last_whitespace_counter == 0) && ((invecj[i] == ' ') || (invecj[i] == '\t') || (invecj[i] == '\n') ||
                                               (invecj[i] == '\r') || (invecj[i] == '\v') || (invecj[i] == '\f')))
        {
            outvecj += ' ';
            last_whitespace_counter += 1;
            continue;
        }
        else if ((last_whitespace_counter != 0) && ((invecj[i] == ' ') || (invecj[i] == '\t') || (invecj[i] == '\n') ||
                                                    (invecj[i] == '\r') || (invecj[i] == '\v') || (invecj[i] == '\f')))
        {
            last_whitespace_counter += 1;
            continue;
        }
        last_whitespace_counter = 0;
        outvecj += invecj[i];
    }
    if ((!outvecj.empty()) && (outvecj.back() == ' '))
    {
        outvecj.resize(outvecj.size() - 1);
    }

    return outvecj;
}
std::string remove_whitespaces(const std::string_view invecj)
{
    std::string outvecj;
    outvecj.reserve(invecj.size());
    for (size_t i = 0; i < invecj.size(); i++)
    {
        if ((invecj[i] == ' ') || (invecj[i] == '\t') || (invecj[i] == '\n') || (invecj[i] == '\r') ||
            (invecj[i] == '\v') || (invecj[i] == '\f'))
        {
            continue;
        }
        outvecj += invecj[i];
    }

    return outvecj;
}
std::string replace_fu(const std::string_view s, int op)
{
    std::string outv;
    outv.reserve(s.size());
    auto siterstart = s.begin();
    auto siterend = s.end();
    if (op == 0)
    {
        while (siterstart != siterend)
        {
            outv += (array_ascii_replace_non_alphanumeric[*siterstart++]);
        }
    }
    else if (op == 1)
    {
        while (siterstart != siterend)
        {
            outv += (array_ascii_replace_non_printable[*siterstart++]);
        }
    }
    else if (op == 2)
    {
        while (siterstart != siterend)
        {
            outv += (array_ascii_replace_non_numeric[*siterstart++]);
        }
    }
    else if (op == 3)
    {
        while (siterstart != siterend)
        {
            outv += (array_ascii_replace_non_numeric_float[*siterstart++]);
        }
    }
    else if (op == 4)
    {
        while (siterstart != siterend)
        {
            outv += (array_ascii_replace_non_numeric_float_with_comma[*siterstart++]);
        }
    }
    return outv;
}

std::string replace_non_alphanumeric_with_spaces(std::string_view _sv)
{
    return replace_fu(_sv, 0);
}
std::string replace_non_printable_with_spaces(std::string_view _sv)
{
    return replace_fu(_sv, 1);
}
std::string replace_non_decimal_with_spaces(std::string_view _sv)
{
    return replace_fu(_sv, 2);
}
std::string replace_non_float_with_spaces(std::string_view _sv)
{
    return replace_fu(_sv, 3);
}
std::string replace_non_float_with_spaces_and_comma(std::string_view _sv)
{
    return replace_fu(_sv, 4);
}
std::vector<std::pair<std::string, std::string>> parse_args_to_string_vector(int argc, char *argv[])
{
    std::vector<std::pair<std::string, std::string>> args;
    args.reserve(argc);
    for (size_t i{0}; i < argc; i++)
    {
        if (i == 0)
        {
            args.emplace_back(std::make_pair("__FILE__", std::string(argv[i])));
        }
        else
        {
            std::string tmpstring{argv[i]};
            size_t idxequal{tmpstring.find('=')};
            if (idxequal != std::string::npos && idxequal > 2)
            {
                args.emplace_back(std::make_pair(tmpstring.substr(2, idxequal - 2), tmpstring.substr(idxequal + 1)));
            }
            // args.push_back(std::make_pair(std::string(argv[i]), std::string(argv[i + 1])));
        }
    }
    return args;
}
static bool compare2strings(const std::string_view s1, const std::string_view s2)
{
    if (s1.size() != s2.size())
    {
        return false;
    }
    auto it1 = s1.begin();
    auto it2 = s2.begin();
    while (it1 != s1.end())
    {
        if (*it1 != *it2)
        {
            return false;
        }
        it1++;
        it2++;
    }
    return true;
}
static bool compare2strings(const char *s1, const std::string_view s2)
{
    const std::string_view s1view{s1};
    return compare2strings(s1view, s2);
}
static bool compare2strings(const char *s1, const char *s2)
{
    const std::string_view s1view{s1};
    const std::string_view s2view{s2};
    return compare2strings(s1view, s2view);
}
static bool compare2strings(const std::string_view s1, const char *s2)
{
    const std::string_view s2view{s2};
    return compare2strings(s1, s2view);
}

static std::vector<int64_t> parse_ints_to_vector(const std::string_view s, char delim = ',',
                                                 int64_t nan_value = MAX_64BIT_INT)
{
    std::vector<int64_t> result;
    result.reserve(s.size() / 4);
    auto strs = s | std::views::split(delim);
    for (const auto &ref : strs)
    {
        std::string_view sv{ref.begin(), ref.end()};
        result.emplace_back(convert_to_int_at_any_cost(sv, nan_value));
    }

    return result;
}
static std::vector<double> parse_doubles_to_vector(const std::string_view s, char delim = ',',
                                                   int64_t nan_value = MAX_64BIT_INT_AS_DOUBLE)
{
    std::vector<double> result;
    result.reserve(s.size() / 4);
    auto strs = s | std::views::split(delim);
    for (const auto &ref : strs)
    {
        std::string_view sv{ref.begin(), ref.end()};
        result.emplace_back(convert_to_double_at_any_cost(sv, nan_value));
    }
    return result;
}
static std::vector<std::pair<int64_t, int64_t>> parse_int_pairs_to_vector(const std::string_view s,
                                                                          int64_t nan_value = MAX_64BIT_INT)
{
    std::string s2{replace_non_float_with_spaces_and_comma(s)};
    std::string s3{normalize_whitespaces(s2)};
    std::vector<std::pair<int64_t, int64_t>> result;
    result.reserve(s.size() / 4);
    auto strs = s3 | std::views::split(' ');
    for (const auto &ref : strs)
    {
        std::string_view sv{ref.begin(), ref.end()};
        auto floatsnumbers = sv | std::views::split(',');
        size_t numbercounter = 0;
        int64_t firstvalueint = nan_value, secondvalueint = nan_value;
        for (const auto &ref2 : floatsnumbers)
        {
            std::string_view first_sv{ref2.begin(), ref2.end()};
            double firstvalue = convert_to_double_at_any_cost(first_sv, (double)nan_value);
            if (numbercounter == 0)
            {
                firstvalueint = (int64_t)firstvalue;
            }
            else if (numbercounter == 1)
            {
                secondvalueint = (int64_t)firstvalue;
            }
            numbercounter++;
        }
        result.emplace_back(std::make_pair(firstvalueint, secondvalueint));
    }
    return result;
}

static std::vector<std::pair<double, double>> parse_double_pairs_to_vector(const std::string_view s,
                                                                           double nan_value = MAX_64BIT_INT_AS_DOUBLE)
{
    std::string s2{replace_non_float_with_spaces_and_comma(s)};
    std::string s3{normalize_whitespaces(s2)};
    std::vector<std::pair<double, double>> result;
    result.reserve(s.size() / 4);
    auto strs = s3 | std::views::split(' ');
    for (const auto &ref : strs)
    {
        std::string_view sv{ref.begin(), ref.end()};
        auto floatsnumbers = sv | std::views::split(',');
        size_t numbercounter = 0;
        double firstvalueint = nan_value, secondvalueint = nan_value;
        for (const auto &ref2 : floatsnumbers)
        {
            std::string_view first_sv{ref2.begin(), ref2.end()};
            double firstvalue = convert_to_double_at_any_cost(first_sv, nan_value);
            if (numbercounter == 0)
            {
                firstvalueint = firstvalue;
            }
            else if (numbercounter == 1)
            {
                secondvalueint = firstvalue;
            }
            numbercounter++;
        }
        result.emplace_back(std::make_pair(firstvalueint, secondvalueint));
    }
    return result;
}
} // namespace arghelpers

#endif
