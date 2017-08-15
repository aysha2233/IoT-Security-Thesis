package org.bouncycastle.est;

import java.io.IOException;

/**
 * ESTSourceConnectionListener is called when the source is
 * is connected to the remote end point but no application
 * data has been sent.
 */
public interface ESTSourceConnectionListener
{
    ESTRequest onConnection(Source source, ESTRequest request)
        throws IOException;
}
