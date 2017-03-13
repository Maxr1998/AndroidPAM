package de.Maxr1998.android_pam.utils;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.iid.FirebaseInstanceId;

public class FirebaseUtils {
    public static void sendTokenToServer() {
        FirebaseAuth mFirebaseAuth = FirebaseAuth.getInstance();
        FirebaseUser mFirebaseUser = mFirebaseAuth.getCurrentUser();
        if (mFirebaseUser == null) {
            return;
        }

        FirebaseDatabase database = FirebaseDatabase.getInstance();
        final DatabaseReference databaseRef = database.getReference();

        DatabaseReference tokenRef = databaseRef.child("users").child(mFirebaseUser.getUid()).child("device_token");
        tokenRef.setValue(FirebaseInstanceId.getInstance().getToken());
    }
}
