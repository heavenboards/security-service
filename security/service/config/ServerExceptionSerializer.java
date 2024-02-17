package security.service.config;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import lombok.SneakyThrows;
import org.springframework.stereotype.Component;
import transfer.contract.exception.ServerException;

/**
 * Класс для корректного маппинга ServerException в JSON.
 */
@Component
public class ServerExceptionSerializer extends StdSerializer<ServerException> {
    /**
     * Пустой конструктор.
     */
    public ServerExceptionSerializer() {
        this(null);
    }

    /**
     * Конструктор с поддерживаемым для сериализации классом.
     *
     * @param clazz - класс
     */
    protected ServerExceptionSerializer(Class<ServerException> clazz) {
        super(clazz);
    }

    /**
     * Перевод ServerException в JSON.
     *
     * @param exception          - ошибка
     * @param jsonGenerator      - генератор JSON
     * @param serializerProvider - serializerProvider
     */
    @Override
    @SneakyThrows
    public void serialize(ServerException exception,
                          JsonGenerator jsonGenerator,
                          SerializerProvider serializerProvider) {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("errorCode", exception.getErrorCode().name());
        jsonGenerator.writeEndObject();
    }
}
