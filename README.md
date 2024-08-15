# webhooks.linu.sk

Webhooks are a way to trigger actions on a server by sending a HTTP request to a specific URL. This service listens for incoming webhooks and triggers the corresponding action.

Also see ["About webhooks" by GitHub](https://docs.github.com/en/webhooks/about-webhooks).


## Tasks

- **GitHub**: If a commit is pushed to some of my GitHub repositories (those deployed on [linu.sk](https://linu.sk)), GitHub sends a POST request to this service, which pulls, builds and deploys the corresponding repository. This has been introduced for [linuskmr/linu.sk#3](https://github.com/linuskmr/linu.sk/issues/3).