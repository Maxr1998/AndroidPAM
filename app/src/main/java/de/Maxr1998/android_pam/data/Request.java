package de.Maxr1998.android_pam.data;

import com.google.firebase.database.IgnoreExtraProperties;

@IgnoreExtraProperties
public class Request {
    public String state;
    public String challenge;
    public String response;

    public Request() {
        state = "idle";
    }
}
