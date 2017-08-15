package org.bouncycastle.math.ec;

import org.bouncycastle.java.math.BigInteger;

public class ReferenceMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        return ECAlgorithms.referenceMultiply(p, k);
    }
}
