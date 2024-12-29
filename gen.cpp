#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Function to add two large numbers represented as strings
std::string addStringNumbers(const std::string &a, const std::string &b)
{
    std::string result;
    int carry = 0;
    int i = a.length() - 1;
    int j = b.length() - 1;

    while (i >= 0 || j >= 0 || carry)
    {
        int sum = carry;
        if (i >= 0)
            sum += a[i--] - '0';
        if (j >= 0)
            sum += b[j--] - '0';
        carry = sum / 10;
        result = char(sum % 10 + '0') + result;
    }

    return result;
}

// Function to subtract two large numbers represented as strings
std::string subtractStringNumbers(const std::string &a, const std::string &b)
{
    std::string result;
    int borrow = 0;
    std::string num1 = a;
    std::string num2 = b;

    // Make the numbers same length by padding with zeros
    while (num1.length() < num2.length())
        num1 = "0" + num1;
    while (num2.length() < num1.length())
        num2 = "0" + num2;

    for (int i = num1.length() - 1; i >= 0; i--)
    {
        int digit1 = num1[i] - '0';
        int digit2 = num2[i] - '0';
        int diff = digit1 - digit2 - borrow;

        if (diff < 0)
        {
            diff += 10;
            borrow = 1;
        }
        else
        {
            borrow = 0;
        }

        result = char(diff + '0') + result;
    }

    // Remove leading zeros
    while (result.length() > 1 && result[0] == '0')
    {
        result.erase(0, 1);
    }

    return result;
}

// Function to divide a large number string by an integer
std::string divideStringByInt(const std::string &number, int divisor)
{
    std::string result;
    int idx = 0;
    int temp = number[idx] - '0';

    while (temp < divisor && idx < number.length() - 1)
    {
        temp = temp * 10 + (number[++idx] - '0');
    }

    while (idx < number.length())
    {
        result += (temp / divisor) + '0';
        temp = (temp % divisor) * 10;
        if (idx + 1 < number.length())
        {
            temp += number[++idx] - '0';
        }
        else
        {
            break;
        }
    }

    if (result.empty())
    {
        return "0";
    }

    return result;
}

int main()
{
    const int NUM_STEPS = 1000000;
    std::string startStr = "21778071482940061661655974875633165533184";
    std::string endStr = "43556142965880123323311949751266331066367";

    std::ofstream outFile("decimals.txt");
    if (!outFile)
    {
        std::cerr << "Could not open file\n";
        return 1;
    }

    outFile << startStr << std::endl;

    // Calculate step size by subtracting start from end and dividing by NUM_STEPS
    std::string difference = subtractStringNumbers(endStr, startStr);
    std::string step = divideStringByInt(difference, NUM_STEPS);

    std::cout << "Starting calculations...\n";
    std::string current = startStr;

    for (int i = 1; i < NUM_STEPS; i++)
    {
        if (i % 100 == 0)
        {
            std::cout << "Progress: " << (i * 100 / NUM_STEPS) << "%\r" << std::flush;
        }

        current = addStringNumbers(current, step);
        outFile << current << std::endl;
    }

    outFile << endStr << std::endl;
    outFile.close();
    std::cout << "\nDone! Numbers have been saved to decimals.txt\n";
    return 0;
}
