-keep class com.ghostnet.** { *; }
-keepclassmembers class com.ghostnet.GhostVpnService {
    public static boolean isRunning;
}
-dontwarn okhttp3.**
