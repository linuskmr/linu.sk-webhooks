.PHONY = build deploy

build:
	go build .

deploy: build
	@echo "Do: sudo systemctl stop webhooks"
	scp webhooks linu.sk:/var/www/webhooks.linu.sk
	@echo "Do: sudo systemctl start webhooks"