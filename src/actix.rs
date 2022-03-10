
#[cfg(test)]
mod tests {
    
    use actix_web::{
        http::{self, header},
        HttpRequest, HttpResponse,
        App,
        web,
        test
    };

    async fn index(req: HttpRequest) -> HttpResponse {
        if let Some(_hdr) = req.headers().get(header::CONTENT_TYPE) {
            HttpResponse::Ok().into()
        } else {
         HttpResponse::BadRequest().into()
        }
    }

    #[actix_web::test]
    async fn test_index_ok() {
        let req = test::TestRequest::default()
            .insert_header(header::ContentType::plaintext())
            .to_http_request();
        let resp = index(req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_index_post() {
        let app = test::init_service(App::new()
        .route("/", web::post().to(index))).await;
        let req = test::TestRequest::post().uri("/")
            .insert_header(header::ContentType::plaintext())
            .set_payload(web::Bytes::from("Hello world")).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }
}