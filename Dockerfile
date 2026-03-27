FROM ruby:3.1.2-alpine

RUN apk add build-base
RUN gem install bundler:2.3.24
RUN mkdir -p /www/example-terminal-backend
WORKDIR /www/example-terminal-backend
COPY . .
RUN bundle install
EXPOSE 4567
RUN chmod +x /www/example-terminal-backend/entrypoint.sh

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /www/example-terminal-backend
USER appuser

ENTRYPOINT ["/www/example-terminal-backend/entrypoint.sh"]
