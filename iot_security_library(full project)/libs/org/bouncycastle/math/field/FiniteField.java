package org.bouncycastle.math.field;

import org.bouncycastle.java.math.BigInteger;

public interface FiniteField
{
    BigInteger getCharacteristic();

    int getDimension();
}
