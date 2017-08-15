package org.bouncycastle.est;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;

/**
 * Holder class for a SimplePKIResponse containing the details making up /cacerts response.
 */
public class CACertsResponse
{
    private final Store store;
    private Store crlHolderStore;
    private final ESTRequest requestToRetry;
    private final Source session;
    private final boolean trusted;

    public CACertsResponse(
        Store store,
        Store crlHolderStore,
        ESTRequest requestToRetry,
        Source session, boolean trusted)
    {
        this.store = store;
        this.requestToRetry = requestToRetry;
        this.session = session;
        this.trusted = trusted;
        this.crlHolderStore = crlHolderStore;
    }

    public boolean hasCertificates()
    {
        return store != null;
    }

    public Store getCertificateStore()
    {
        if (store == null)
        {
            throw new IllegalStateException("Response has no certificates.");
        }
        return store;
    }


    public boolean hasCRLs()
    {
        return crlHolderStore != null;
    }

    public Store getCrlStore()
    {
        if (crlHolderStore == null)
        {
            throw new IllegalStateException("Response has no CRLs.");
        }
        return crlHolderStore;
    }


    public ESTRequest getRequestToRetry()
    {
        return requestToRetry;
    }

    public Object getSession()
    {
        return session.getSession();
    }

    public boolean isTrusted()
    {
        return trusted;
    }
}
