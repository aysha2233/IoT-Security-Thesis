package org.bouncycastle.math.ec.endo;

import org.bouncycastle.java.math.BigInteger;

public interface GLVEndomorphism extends ECEndomorphism
{
    BigInteger[] decomposeScalar(BigInteger k);
}
