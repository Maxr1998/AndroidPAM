package de.Maxr1998.android_pam.utils;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static de.Maxr1998.android_pam.Common.KEY_FOOTER;
import static de.Maxr1998.android_pam.Common.KEY_HEADER;
import static de.Maxr1998.android_pam.Common.KEY_NAME;
import static de.Maxr1998.android_pam.Common.LOG_TAG;
import static de.Maxr1998.android_pam.Common.PUBKEY_FILE;
import static de.Maxr1998.android_pam.utils.MiscUtils.bytesToHex;
import static de.Maxr1998.android_pam.utils.MiscUtils.saveFileToStorage;
import static de.Maxr1998.android_pam.utils.MiscUtils.writeToStream;

public final class KeyUtils {

    private static final int PUBLIC_KEY_LENGTH = 64;
    private static final int PRIVATE_KEY_LENGTH = 32;

    @NonNull
    public static String getPublicKeyAsHex(PublicKey publicKey) {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECPoint ecPoint = ecPublicKey.getW();

        byte[] publicKeyBytes = new byte[PUBLIC_KEY_LENGTH];
        writeToStream(publicKeyBytes, 0, ecPoint.getAffineX(), PRIVATE_KEY_LENGTH);
        writeToStream(publicKeyBytes, PRIVATE_KEY_LENGTH, ecPoint.getAffineY(), PRIVATE_KEY_LENGTH);
        return bytesToHex(publicKeyBytes);
    }

    public static void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setUserAuthenticationRequired(true)
                            .build());
            keyPairGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static PublicKey bytesToKey(byte[] key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        return factory.generatePublic(spec);
    }

    @NonNull
    /**
     * Convert public key to X.509-encoded pem String
     */
    public static String convertKeyToPEM(@NonNull PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KEY_HEADER + Base64.encodeToString(bytesToKey(key.getEncoded()).getEncoded(), Base64.DEFAULT) + KEY_FOOTER;
    }

    public static void showPublicKey(final Context c, @NonNull KeyStore keyStore) {
        try {
            keyStore.load(null);
            PublicKey key = keyStore.getCertificate(KEY_NAME).getPublicKey();
            Log.d(LOG_TAG, "PUBLIC_KEY | " + KeyUtils.getPublicKeyAsHex(key));

            // Convert to pem, save, log and display
            final String pem = convertKeyToPEM(key);
            saveFileToStorage(c, PUBKEY_FILE, pem);
            Log.d(LOG_TAG, pem);
            new AlertDialog.Builder(c)
                    .setTitle("PUBLIC KEY")
                    .setMessage(pem)
                    .setPositiveButton("Copy to clipboard", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                            ClipboardManager clipboard = (ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
                            clipboard.setPrimaryClip(ClipData.newPlainText("Public key", pem));
                        }
                    })
                    .setNegativeButton(android.R.string.cancel, null).create().show();
        } catch (CertificateException | InvalidKeySpecException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}