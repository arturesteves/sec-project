package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import spark.Request;

import java.io.IOException;

public class Serialization {
    private static ObjectMapper mapper = new ObjectMapper();

    public static class RegisterRequest {
        // TODO add remaining fields
        public String key;
    }

    public static class SendAmountRequest {
        // TODO add remaining fields
        public String source;
        public String destination;
        public int amount;
    }

    public static class ReceiveAmountRequest {
        // TODO add remaining fields
        public String source;
    }

    public static <T> T parse(Request request, Class<T> valueType) throws IOException {
        return mapper.readValue(request.body(), valueType);
    }
}
