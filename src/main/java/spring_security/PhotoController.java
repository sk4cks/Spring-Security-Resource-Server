package spring_security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class PhotoController {

    @GetMapping("/photos")
    public List<Photo> photos() {

        Photo photo1 = getPhoto("1", "Photo 1 Title", "Photo is nice", "user1");
        Photo photo2 = getPhoto("2", "Photo 2 Title", "Photo is beautiful", "user2");

        return Arrays.asList(photo1,photo2);
    }

    @GetMapping("/remotePhotos")
    public List<Photo> remotePhotos() {

        Photo photo1 = getPhoto("Remote 1", "Remote Photo 1 Title", "Remote Photo is nice", "Remote user1");
        Photo photo2 = getPhoto("Remote 2", "Remote Photo 2 Title", "Remote Photo is beautiful", "Remote user2");

        return Arrays.asList(photo1,photo2);
    }

    private Photo getPhoto(String photoId, String photoTitle, String photoDesc, String userId) {
        return Photo.builder()
                .photoId(photoId)
                .photoTitle(photoTitle)
                .photoDescription(photoDesc)
                .userId(userId)
                .build();
    }
}
