package spring_security;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Photo {

    private String photoId;
    private String photoTitle;
    private String photoDescription;
    private String userId;
}
