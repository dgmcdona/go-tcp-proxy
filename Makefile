tcp-proxy:
	sudo DOCKER_BUILDKIT=1 docker build --target export -t test . --output .

clean:
	rm tcp-proxy
