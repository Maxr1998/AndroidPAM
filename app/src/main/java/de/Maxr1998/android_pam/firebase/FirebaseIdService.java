package de.Maxr1998.android_pam.firebase;

import com.google.firebase.iid.FirebaseInstanceIdService;

import de.Maxr1998.android_pam.utils.FirebaseUtils;

public class FirebaseIdService extends FirebaseInstanceIdService {

    @Override
    public void onTokenRefresh() {
        FirebaseUtils.sendTokenToServer();
    }
}
