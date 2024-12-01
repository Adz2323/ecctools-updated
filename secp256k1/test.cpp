#include <stdio.h>
#include <string.h>
#include <string>
#include "SECP256k1.h"
#include "Point.h"
#include "Int.h"

void printPoint(const char *label, Point &p)
{
    printf("%s: (%s, %s)\n", label, p.x.GetBase16(), p.y.GetBase16());
}

bool testPointAddition()
{
    printf("\nTesting Point Addition...\n");
    Secp256K1 secp;
    secp.Init();

    Point zero;
    zero.setInfinity();
    Point result = secp.Add(secp.G, zero);

    printf("\nTesting G + 0:\n");
    if (!result.debugEquals(secp.G))
    {
        printf("FAILED: G + 0 != G\n");
        return false;
    }

    return true;
}

bool testPointDoubling()
{
    printf("\nTesting Point Doubling...\n");
    Secp256K1 secp;
    secp.Init();

    Point double_g = secp.Double(secp.G);
    Point add_g = secp.Add(secp.G, secp.G);

    printf("\nTesting Double(G) == G + G:\n");
    if (!double_g.debugEquals(add_g))
    {
        printf("FAILED: Double(G) != G + G\n");
        printPoint("Double result", double_g);
        printPoint("Addition result", add_g);
        return false;
    }

    return true;
}

bool testIdentityPointOperations()
{
    printf("\nTesting Identity Point Operations...\n");
    Secp256K1 secp;
    secp.Init();

    Point zero;
    zero.setInfinity();

    // Test G + 0
    Point result = secp.Add(secp.G, zero);
    printf("\nTesting G + 0 == G:\n");
    if (!result.debugEquals(secp.G))
    {
        printf("FAILED: G + 0 != G\n");
        return false;
    }

    // Test G + (-G)
    Point negG = secp.Negation(secp.G);
    result = secp.Add(secp.G, negG);
    printf("\nTesting G + (-G) == 0:\n");
    if (!result.isZero())
    {
        printf("Result of G + (-G):\n");
        result.debugEquals(zero);
        printf("FAILED: G + (-G) != 0\n");
        return false;
    }

    return true;
}

bool testSpecialCases()
{
    printf("\nTesting Special Cases...\n");
    Secp256K1 secp;
    secp.Init();

    Point zero;
    zero.setInfinity();
    Point result = secp.Add(secp.G, zero);

    printf("\nTesting G + 0 == G (special case):\n");
    if (!result.debugEquals(secp.G))
    {
        printf("FAILED: G + 0 != G\n");
        return false;
    }

    return true;
}

bool testBasicOperations()
{
    printf("\nTesting Basic Point Operations...\n");
    Secp256K1 secp;
    secp.Init();

    Point sum = secp.Add(secp.G, secp.G);
    Point dbl = secp.Double(secp.G);

    printf("G + G coordinates:\n");
    printf("x: %s\n", sum.x.GetBase16());
    printf("y: %s\n", sum.y.GetBase16());

    printf("2G coordinates:\n");
    printf("x: %s\n", dbl.x.GetBase16());
    printf("y: %s\n", dbl.y.GetBase16());

    printf("\nTesting G + G == 2G:\n");
    if (!sum.debugEquals(dbl))
    {
        printf("FAILED: G + G != 2G in basic test\n");
        return false;
    }

    // Test G + (-G)
    Point negG = secp.Negation(secp.G);
    Point shouldBeIdentity = secp.Add(secp.G, negG);

    printf("\nTesting G + (-G) == 0:\n");
    if (!shouldBeIdentity.isZero())
    {
        printf("FAILED: G + (-G) is not identity\n");
        printf("z coordinate: %s\n", shouldBeIdentity.z.GetBase16());
        return false;
    }

    return true;
}

bool testPublicKeyParsing()
{
    printf("\nTesting Public Key Parsing...\n");
    Secp256K1 secp;
    secp.Init();

    // Test parsing uncompressed public key
    char uncompressed[] = "04"
                          "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                          "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    Point parsed;
    bool isCompressed;
    if (!secp.ParsePublicKeyHex(uncompressed, parsed, isCompressed))
    {
        printf("FAILED: Unable to parse uncompressed public key\n");
        return false;
    }

    printf("\nTesting parsed key == G:\n");
    if (!parsed.debugEquals(secp.G))
    {
        printf("FAILED: Parsed uncompressed key doesn't match generator point\n");
        return false;
    }

    if (isCompressed)
    {
        printf("FAILED: Uncompressed key reported as compressed\n");
        return false;
    }

    printf("Public Key Parsing tests passed\n");
    return true;
}

bool testPointOnCurve()
{
    printf("\nTesting Point on Curve Validation...\n");
    Secp256K1 secp;
    secp.Init();

    // Test generator point
    if (!secp.EC(secp.G))
    {
        printf("FAILED: Generator point not on curve\n");
        return false;
    }

    // Test invalid point
    Point invalid;
    invalid.x.SetInt32(1);
    invalid.y.SetInt32(1);
    invalid.z.SetInt32(1);

    if (secp.EC(invalid))
    {
        printf("FAILED: Invalid point reported as valid\n");
        return false;
    }

    printf("Point on Curve Validation tests passed\n");
    return true;
}

bool testScalarMultiplication()
{
    printf("\nTesting Scalar Multiplication...\n");
    Secp256K1 secp;
    secp.Init();

    Int two;
    two.SetInt32(2);
    printf("\nScalar value: %s\n", two.GetBase16());

    Point double_g = secp.Double(secp.G);
    printf("\nDouble(G) result:\n");
    printf("x: %s\n", double_g.x.GetBase16());
    printf("y: %s\n", double_g.y.GetBase16());
    printf("z: %s\n", double_g.z.GetBase16());

    Point result = secp.ScalarMultiplication(secp.G, &two);
    printf("\nScalarMult result:\n");
    printf("x: %s\n", result.x.GetBase16());
    printf("y: %s\n", result.y.GetBase16());
    printf("z: %s\n", result.z.GetBase16());

    printf("\nComparing results:\n");
    if (!result.debugEquals(double_g))
    {
        printf("FAILED: G * 2 != Double(G)\n");
        printPoint("Result", result);
        printPoint("Expected", double_g);
        return false;
    }

    return true;
}

bool testExtendedScalarMultiplication()
{
    printf("\nTesting Extended Scalar Multiplication...\n");

    // Test vectors from https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
    struct TestVector
    {
        uint32_t scalar;
        const char *x;
        const char *y;
    };

    TestVector vectors[] = {
        {2, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
         "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"},
        {3, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
         "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"},
        {4, "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
         "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922"},
        {5, "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
         "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"},
        {8, "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
         "ae04d987d2c53a0d879709784b7d571827a23194a6877d81fda25294364f5363"}};

    Secp256K1 secp;
    secp.Init();

    // Test known values
    printf("\nTesting known scalar values...\n");
    for (const auto &test : vectors)
    {
        Int scalar;
        scalar.SetInt32(test.scalar);

        Point result = secp.ScalarMultiplication(secp.G, &scalar, true); // Enable debug for failing cases

        Point expected;
        expected.x.SetBase16(test.x);
        expected.y.SetBase16(test.y);
        expected.z.SetInt32(1);

        printf("\nTesting %dG:\n", test.scalar);
        printf("Expected:\nx: %s\ny: %s\n", test.x, test.y);
        printf("Got:\nx: %s\ny: %s\n", result.x.GetBase16(), result.y.GetBase16());

        if (!result.equals(expected))
        {
            printf("FAILED: %dG mismatch\n", test.scalar);
            return false;
        }
    }

    printf("Extended Scalar Multiplication tests passed\n");
    return true;
}

int main()
{
    bool allTestsPassed = true;

    // Run all tests
    allTestsPassed &= testPointAddition();
    allTestsPassed &= testPointDoubling();
    allTestsPassed &= testScalarMultiplication();
    allTestsPassed &= testPublicKeyParsing();
    allTestsPassed &= testPointOnCurve();
    allTestsPassed &= testIdentityPointOperations();
    allTestsPassed &= testSpecialCases();
    allTestsPassed &= testBasicOperations();
    allTestsPassed &= testExtendedScalarMultiplication();

    if (allTestsPassed)
    {
        printf("\nAll tests PASSED!\n");
    }
    else
    {
        printf("\nSome tests FAILED!\n");
    }

    return allTestsPassed ? 0 : 1;
}
