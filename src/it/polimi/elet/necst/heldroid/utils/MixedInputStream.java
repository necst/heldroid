package it.polimi.elet.necst.heldroid.utils;

import java.io.IOException;
import java.io.InputStream;

public class MixedInputStream extends InputStream {
    private static final int PARTIAL_BUFFER_MAX_SIZE = 4096;

    private InputStream stream;
    private byte[] partialBuffer;
    private int partialBufferIndex;

    public MixedInputStream(InputStream stream) {
        this.stream = stream;
        this.partialBuffer = null;
        this.partialBufferIndex = -1;
    }

    @Override
    public int read() throws IOException {
        return stream.read();
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        if (partialBuffer == null)
            return stream.read(buffer, offset, length);

        int remainingBufferSize = partialBuffer.length - partialBufferIndex;

        if (remainingBufferSize >= length) {
            System.arraycopy(partialBuffer, partialBufferIndex, buffer, offset, length);
            partialBufferIndex += length;

            if (partialBufferIndex == partialBuffer.length) {
                partialBuffer = null;
                partialBufferIndex = -1;
            }

            return length;
        }

        System.arraycopy(partialBuffer, partialBufferIndex, buffer, offset, remainingBufferSize);

        partialBuffer = null;
        partialBufferIndex = -1;

        int readBytes = stream.read(buffer, offset + remainingBufferSize, length - remainingBufferSize);

        return remainingBufferSize + readBytes;
    }

    public String readLine() throws IOException {
        if (partialBuffer == null)
            this.refillPartialBuffer();

        StringBuilder builder = new StringBuilder();
        boolean nrFound = false;
        int i;

        do {
            for (i = partialBufferIndex ; i < partialBuffer.length; i++) {
                if (partialBuffer[i] != 13)
                    builder.append((char)partialBuffer[i]);
                else {
                    if ((i + 1 < partialBuffer.length) && (partialBuffer[i + 1] == 10))
                        i++;

                    nrFound = true;
                    break;
                }
            }

            if (!nrFound && (i >= partialBuffer.length))
                this.refillPartialBuffer();
        } while (!nrFound);

        partialBufferIndex = i + 1;

        if (partialBufferIndex >= partialBuffer.length) {
            partialBuffer = null;
            partialBufferIndex = -1;
        }

        return builder.toString();
    }

    public void skipEmptyLines() throws IOException {
        if (partialBuffer == null)
            this.refillPartialBuffer();

        boolean cFound = false;
        int i;

        do {
            for (i = partialBufferIndex; i < partialBuffer.length; i++)
                if (partialBuffer[i] == 13) {
                    if ((i + 1 < partialBuffer.length) && (partialBuffer[i + 1] == 10))
                        i++;
                } else {
                    cFound = true;
                    break;
                }

            if (!cFound && (i >= partialBuffer.length))
                this.refillPartialBuffer();
        } while (!cFound);

        partialBufferIndex = i;
    }

    private void refillPartialBuffer() throws IOException {
        byte[] tempBuffer = new byte[PARTIAL_BUFFER_MAX_SIZE];
        int actualLength = stream.read(tempBuffer, 0, tempBuffer.length);

        partialBuffer = new byte[actualLength];
        partialBufferIndex = 0;

        System.arraycopy(tempBuffer, 0, partialBuffer, 0, actualLength);
    }
}
