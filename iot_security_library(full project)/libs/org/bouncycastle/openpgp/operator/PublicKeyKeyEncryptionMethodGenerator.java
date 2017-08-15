package org.bouncycastle.openpgp.operator;

import java.io.IOException;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.java.math.BigInteger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

public abstract class PublicKeyKeyEncryptionMethodGenerator
    extends PGPKeyEncryptionMethodGenerator
{
    private PGPPublicKey pubKey;

    protected PublicKeyKeyEncryptionMethodGenerator(
        PGPPublicKey pubKey)
    {
        this.pubKey = pubKey;

        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            break;
        case PGPPublicKey.RSA_SIGN:
            throw new IllegalArgumentException("Can't use an RSA_SIGN key for encryption.");
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            break;
        case PGPPublicKey.ECDH:
            break;
        case PGPPublicKey.DSA:
            throw new IllegalArgumentException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new IllegalArgumentException("Can't use ECDSA for encryption.");
        default:
            throw new IllegalArgumentException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }
    }

    public byte[][] processSessionInfo(
        byte[] encryptedSessionInfo)
        throws PGPException
    {
        byte[][] data;

        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            data = new byte[1][];

            data[0] = convertToEncodedMPI(encryptedSessionInfo);
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            byte[] b1 = new byte[encryptedSessionInfo.length / 2];
            byte[] b2 = new byte[encryptedSessionInfo.length / 2];

            System.arraycopy(encryptedSessionInfo, 0, b1, 0, b1.length);
            System.arraycopy(encryptedSessionInfo, b1.length, b2, 0, b2.length);

            data = new byte[2][];
            data[0] = convertToEncodedMPI(b1);
            data[1] = convertToEncodedMPI(b2);
            break;
        case PGPPublicKey.ECDH:
            data = new byte[1][];

            data[0] = encryptedSessionInfo;
            break;
        default:
            throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        return data;
    }

    private byte[] convertToEncodedMPI(byte[] encryptedSessionInfo)
        throws PGPException
    {
        try
        {
            return new MPInteger(new BigInteger(1, encryptedSessionInfo)).getEncoded();
        }
        catch (IOException e)
        {
            throw new PGPException("Invalid MPI encoding: " + e.getMessage(), e);
        }
    }

    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        return new PublicKeyEncSessionPacket(pubKey.getKeyID(), pubKey.getAlgorithm(), processSessionInfo(encryptSessionInfo(pubKey, sessionInfo)));
    }

    abstract protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException;
}
