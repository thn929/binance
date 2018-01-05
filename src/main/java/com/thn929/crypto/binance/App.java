package com.thn929.crypto.binance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class App {

    public static void main(String[] args) throws IOException {
        final String apiKey = Files.lines(Paths.get(System.getProperty("user.home") + "/binance/apiKey")).findFirst().get();
        final String secretKey = Files.lines(Paths.get(System.getProperty("user.home") + "/binance/secretKey")).findFirst().get();

        final long currentTimeMillis = System.currentTimeMillis();
        final String baseUrl = "https://api.binance.com/api/v3";
        final String endPoint = "/account";
        final String requestParams = "timestamp=" + currentTimeMillis;
        final String signatureParam = "signature=" + hmacSha256Signature(secretKey, requestParams);

        System.out.println(signatureParam);

        final OkHttpClient client = new OkHttpClient();

        final Request request = new Request.Builder()
                .header("X-MBX-APIKEY", apiKey)
                .url(baseUrl + endPoint + "?" + requestParams + "&" + signatureParam)
                .get()
                .build();

        System.out.println(request.url());

        final Response response = client.newCall(request).execute();
        prettyPrintJson(response.body().string());
    }

    private static String hmacSha256Signature(final String secretKey, final String requestParams) {
        try {
            final Charset asciiCs = Charset.forName("US-ASCII");
            final Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            final SecretKeySpec secret_key = new javax.crypto.spec.SecretKeySpec(asciiCs.encode(secretKey).array(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            final byte[] mac_data = sha256_HMAC.doFinal(asciiCs.encode(requestParams).array());
            String result = "";
            for (final byte element : mac_data)
            {
                result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return "";
    }

    private static void prettyPrintJson(String string) {
        final Gson gson = new GsonBuilder().setPrettyPrinting().create();
        final JsonParser jsonParser = new JsonParser();
        final JsonElement jsonElement = jsonParser.parse(string);
        System.out.println(gson.toJson(jsonElement));
    }
}
