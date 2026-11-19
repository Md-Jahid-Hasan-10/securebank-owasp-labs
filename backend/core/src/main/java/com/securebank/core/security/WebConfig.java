package com.securebank.core.security;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final Path assetDirectory;

    public WebConfig(@Value("${app.asset-dir:static/assets}") String assetDir) {
        this.assetDirectory = Paths.get(assetDir).toAbsolutePath().normalize();
    }


    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                // FIXED: [A07-Lab18] Session Fixation - the session id is now
                // regenerated at the moment privileges change, so a cookie planted
                // before the login is abandoned. The CORS settings below are kept
                // narrow for the same reason: only the development frontend origins
                // are allowed, and credentials are only ever sent to those.
                .allowedOriginPatterns("http://localhost:*", "http://127.0.0.1:*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true);
    }

    /**
     * Serves the static asset directory.
     *
     * <p>FIXED: [A08-Lab22] Unrestricted File Upload - the uploads directory used to
     * be mapped as a static resource handler, so any file dropped there by the upload
     * endpoint was served back verbatim with no authentication, no content-type
     * sniffing protection and no download disposition. A .html or .svg file became an
     * active payload in the victim's browser; a .jsp file became server-side code on
     * a container that interprets it.</p>
     *
     * <p>NOW: uploads are stored outside the web root and are served by a dedicated
     * controller that sets Content-Disposition: attachment and a fixed
     * application/octet-stream content type. There is no static handler for them at
     * all, so nothing a user uploads can ever be interpreted by the browser as
     * markup or by the container as code.</p>
     *
     * <p>FIXED: [A02-Lab6] Sensitive File Exposure - this handler used to map
     * {@code /**} at the web root and to map {@code /.env} and {@code /.git/**}
     * explicitly. The former served everything that was dropped into the static
     * tree, and the latter deliberately undid Spring Boot's default protection
     * against dot-prefixed paths. Both mappings are gone; assets are now served
     * from a dedicated directory that contains nothing but assets.</p>
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // FIXED: [A02-Lab6] Sensitive File Exposure - static assets are now served
        // from a dedicated directory that contains nothing but assets. The previous
        // "/**" handler exposed the entire web root, so /.env, /.git/config and
        // backup.zip were downloadable by anyone without authentication.
        //
        // The explicit "/.env" and "/.git/**" handlers have been removed: Spring
        // Boot's default static resource handling deliberately refuses to serve
        // dot-prefixed paths, and those handlers undid that protection.
        //
        // Nothing is mapped at "/**" any more, so a secret file that is accidentally
        // dropped into the asset directory is no longer reachable by default.
        registry.addResourceHandler("/assets/**")
                .addResourceLocations(assetDirectory.toUri().toString());
    }

}
