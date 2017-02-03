package de.Maxr1998.android_pam;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.database.DataSnapshot;
import com.google.firebase.database.DatabaseError;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.ValueEventListener;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import de.Maxr1998.android_pam.data.Request;
import de.Maxr1998.android_pam.utils.KeyUtils;

import static de.Maxr1998.android_pam.Common.FB_LOG;
import static de.Maxr1998.android_pam.Common.KEY_FOOTER;
import static de.Maxr1998.android_pam.Common.KEY_HEADER;
import static de.Maxr1998.android_pam.Common.LOG_TAG;
import static de.Maxr1998.android_pam.Common.PUBKEY_FILE;
import static de.Maxr1998.android_pam.Common.SIG_TYPE;
import static de.Maxr1998.android_pam.utils.MiscUtils.readFileFromStorage;

public class VerifyActivity extends AppCompatActivity implements ValueEventListener {

    private DatabaseReference requestReference;
    private Request currentRequest;

    private SecureRandom random = new SecureRandom();
    private String challenge;

    public String nextChallenge() {
        return new BigInteger(130, random).toString(32);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.verify_activity);

        FirebaseUser mFirebaseUser = FirebaseAuth.getInstance().getCurrentUser();
        if (mFirebaseUser == null) {
            finish();
            return;
        }

        // Set up real-time database
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        final DatabaseReference databaseRef = database.getReference();

        requestReference = databaseRef.child("users").child(mFirebaseUser.getUid()).child("request");

        currentRequest = new Request();
        currentRequest.state = "auth";
        currentRequest.challenge = challenge = nextChallenge();
        update();
        requestReference.addValueEventListener(this);
    }

    @Override
    public void onDataChange(DataSnapshot dataSnapshot) {
        currentRequest = dataSnapshot.getValue(Request.class);
        if (currentRequest.state.equals("signed")) {
            String response = currentRequest.response;
            if (response == null || response.length() == 0)
                return;
            verify(response);
        }
    }

    private void verify(String data) {
        Log.d(LOG_TAG, "Verifying: " + data);
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            byte[] keyFile = readFileFromStorage(VerifyActivity.this, PUBKEY_FILE);
            if (keyFile == null) {
                return;
            }
            String publicKeyPEM = new String(keyFile);
            publicKeyPEM = publicKeyPEM.replace(KEY_HEADER, "").replace(KEY_FOOTER, "");
            byte[] decoded = Base64.decode(publicKeyPEM, Base64.DEFAULT);

            Signature signature = Signature.getInstance(SIG_TYPE);
            signature.initVerify(KeyUtils.bytesToKey(decoded));
            signature.update(challenge.getBytes());

            findViewById(R.id.progress).setVisibility(View.GONE);
            byte[] signed = Base64.decode(data, Base64.DEFAULT);
            if (signature.verify(signed)) {
                Log.d(LOG_TAG, "Success");
                CheckBox success = (CheckBox) findViewById(R.id.success);
                success.setVisibility(View.VISIBLE);
                success.setChecked(true);
            } else {
                throw new SignatureException("Wrong signature");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            challenge = null;
            requestReference.removeEventListener(this);
            currentRequest = new Request();
            update();
        }
    }

    @Override
    protected void onDestroy() {
        if (requestReference != null) {
            requestReference.removeEventListener(this);
            currentRequest = new Request();
            update();
        }
        super.onDestroy();
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
}