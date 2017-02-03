package de.Maxr1998.android_pam.utils;

import android.content.Context;
import android.os.Environment;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public final class MiscUtils {

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static void writeToStream(byte[] stream, int start, BigInteger value, int size) {
        byte[] data = value.toByteArray();
        int length = Math.min(size, data.length);
        int writeStart = start + size - length;
        int readStart = data.length - length;
        System.arraycopy(data, readStart, stream, writeStart, length);
    }

    @NonNull
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars).toLowerCase();
    }

    public static void saveFileToStorage(Context c, @NonNull String fileName, @NonNull String content) {
        saveFileToStorage(c, fileName, content.getBytes());
    }

    public static void saveFileToStorage(Context c, @NonNull String fileName, @NonNull byte[] content) {
        try {
            FileOutputStream out = new FileOutputStream(new File(Environment.getExternalStorageDirectory(), fileName));
            out.write(content);
            out.flush();
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Nullable
    public static byte[] readFileFromStorage(Context c, @NonNull String fileName) {
        try {
            FileInputStream in = new FileInputStream(new File(Environment.getExternalStorageDirectory(), fileName));
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            int i;
            while ((i = in.read(buffer)) != -1) {
                bytes.write(buffer, 0, i);
            }
            in.close();
            return bytes.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
