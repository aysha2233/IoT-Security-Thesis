package org.bouncycastle.cert;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.java.math.BigInteger;
import org.bouncycastle.operator.ContentSigner;


/**
 * class to produce an X.509 Version 1 certificate.
 */
public class X509v1CertificateBuilder
{
    private V1TBSCertificateGenerator   tbsGen;

    /**
     * Create a builder for a version 1 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKeyInfo the info structure for the public key to be associated with this certificate.
     */
    public X509v1CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
    {
        this(issuer, serial, new Time(notBefore), new Time(notAfter), subject, publicKeyInfo);
    }

   /**
    * Create a builder for a version 1 certificate.
    *
    * @param issuer the certificate issuer
    * @param serial the certificate serial number
    * @param notBefore the Time before which the certificate is not valid
    * @param notAfter the Time after which the certificate is not valid
    * @param subject the certificate subject
    * @param publicKeyInfo the info structure for the public key to be associated with this certificate.
    */
   public X509v1CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
   {
       if (issuer == null)
       {
           throw new IllegalArgumentException("issuer must not be null");
       }

       if (publicKeyInfo == null)
       {
           throw new IllegalArgumentException("publicKeyInfo must not be null");
       }

       tbsGen = new V1TBSCertificateGenerator();
       tbsGen.setSerialNumber(new ASN1Integer(serial));
       tbsGen.setIssuer(issuer);
       tbsGen.setStartDate(notBefore);
       tbsGen.setEndDate(notAfter);
       tbsGen.setSubject(subject);
       tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
   }

    /**
     * Generate an X509 certificate, based on the current issuer and subject
     * using the passed in signer.
     *
     * @param signer the content signer to be used to generate the signature validating the certificate.
     * @return a holder containing the resulting signed certificate.
     */
    public X509CertificateHolder build(
        ContentSigner signer)
    {
        tbsGen.setSignature(signer.getAlgorithmIdentifier());

        return CertUtils.generateFullCert(signer, tbsGen.generateTBSCertificate());
    }
}
