package org.bouncycastle.crypto.ec;

import org.bouncycastle.java.math.BigInteger;

public interface ECPairFactorTransform
    extends ECPairTransform
{
    /**
     * Return the last value used to calculated a transform.
     *
     * @return a BigInteger representing the last transform value used.
     */
    BigInteger getTransformValue();
}
