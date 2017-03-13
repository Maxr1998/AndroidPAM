package de.Maxr1998.android_pam;

import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.Nullable;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.database.DataSnapshot;
import com.google.firebase.database.DatabaseError;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.ValueEventListener;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import de.Maxr1998.android_pam.data.Request;
import de.Maxr1998.android_pam.utils.KeyUtils;

import static de.Maxr1998.android_pam.Common.FB_LOG;
import static de.Maxr1998.android_pam.Common.KEY_NAME;
import static de.Maxr1998.android_pam.Common.SIG_TYPE;

public class MainActivity extends AppCompatActivity implements ValueEventListener {
    private FirebaseAuth mFirebaseAuth;
    private FirebaseUser mFirebaseUser;
    private DatabaseReference requestReference;
    private Request currentRequest;

    private KeyStore keyStore;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main_activity);

        // Initialize Firebase Auth
        mFirebaseAuth = FirebaseAuth.getInstance();
        mFirebaseUser = mFirebaseAuth.getCurrentUser();
        if (mFirebaseUser == null) {
            // Not signed in, launch the Sign in activity
            startActivity(new Intent(this, SignInActivity.class));
            finish();
            return;
        }
        // Set up real-time database
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        final DatabaseReference databaseRef = database.getReference();

        requestReference = databaseRef.child("users").child(mFirebaseUser.getUid()).child("request");
        requestReference.addValueEventListener(this);

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onDataChange(DataSnapshot dataSnapshot) {
        currentRequest = dataSnapshot.getValue(Request.class);
        // Set initial
        if (currentRequest == null) {
            update();
            return;
        }
        if (currentRequest.state.equals("request")) {
            String challenge = currentRequest.challenge;
            if (challenge == null || challenge.length() == 0)
                return;
            currentRequest.challenge = null;
            update();
            sign(challenge);
        }
    }

    @Override
    public void onCancelled(DatabaseError databaseError) {
        Log.w(FB_LOG, "loadPost:onCancelled", databaseError.toException());
    }

    private void update() {
        if (currentRequest == null) {
            currentRequest = new Request();
        }
        requestReference.setValue(currentRequest);
    }

    private void sign(final String data) {
        try {
            if (keyStore == null) {
                return;
            }
            // Load signature and keystore
            keyStore.load(null);
            Signature signature = Signature.getInstance(SIG_TYPE);
            signature.initSign((PrivateKey) keyStore.getKey(KEY_NAME, null));
            FingerprintManagerCompat.CryptoObject cryptObject = new FingerprintManagerCompat.CryptoObject(signature);

            // Show dialog
            Toast.makeText(MainActivity.this, String.format("Received challenge: %1$s", data), Toast.LENGTH_LONG).show();

            // Authenticate
            FingerprintManagerCompat.from(this).authenticate(cryptObject, 0, null, new FingerprintManagerCompat.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                    Signature unlockedSignature = result.getCryptoObject().getSignature();
                    try {
                        unlockedSignature.update(data.getBytes());
                        byte[] signed = unlockedSignature.sign();
                        String encoded = Base64.encodeToString(signed, Base64.DEFAULT).replace("\n", "");
                        if (currentRequest != null) {
                            requestReference.removeEventListener(MainActivity.this);
                            currentRequest.state = "signed";
                            currentRequest.response = encoded;
                            update();
                        }
                    } catch (SignatureException e) {
                        e.printStackTrace();
                    }
                    finish();
                }

                @Override
                public void onAuthenticationError(int errMsgId, CharSequence errString) {
                    finish();
                    Toast.makeText(MainActivity.this, errString, Toast.LENGTH_LONG).show();
                }
            }, null);
        } catch (CertificateException | InvalidKeyException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            Toast.makeText(this, "Error: " + e.getClass().getSimpleName(), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        if (mFirebaseUser != null && mFirebaseUser.getPhotoUrl() != null) {
            final MenuItem login = menu.findItem(R.id.login_info);
            final Handler h = new Handler();
            new Thread() {
                @Override
                public void run() {
                    try {
                        HttpURLConnection connection = (HttpURLConnection) new URL(mFirebaseUser.getPhotoUrl().toString()).openConnection();
                        final BitmapDrawable drawable = new BitmapDrawable(getResources(), BitmapFactory.decodeStream(connection.getInputStream()));
                        h.post(new Runnable() {
                            @Override
                            public void run() {
                                login.setIcon(drawable);
                            }
                        });
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }.start();
        }
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.sign_out:
                mFirebaseAuth.signOut();
                startActivity(new Intent(this, SignInActivity.class));
                finish();
                return true;
            case R.id.create_key:
                KeyUtils.generateKeys();
            case R.id.show_key:
                if (keyStore != null) {
                    KeyUtils.showPublicKey(this, keyStore);
                }
                return true;
            case R.id.debug_verify:
                requestReference.removeEventListener(MainActivity.this);
                startActivity(new Intent(this, VerifyActivity.class));
                finish();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }
}