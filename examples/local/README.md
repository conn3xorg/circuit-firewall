# Local example

Applies circuit-firewall to a throwaway Rocky Linux 10 container with systemd. You need Conn3x and Podman.

The container runs privileged so its firewall can load netfilter rules, which is simplest with rootful Podman. On a Mac, use the Podman machine's root connection. On Linux, use `sudo podman`:

```sh
export CONTAINER_CONNECTION=podman-machine-default-root   # macOS
export PODMAN="sudo podman"                               # Linux
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` To look at the result:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 firewall-cmd --list-all
```

Podman forwards `127.0.0.1:2222` to sshd's port 22 in the container, so the example sets `ssh_allow = ["22/tcp"]`.

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses. On Debian and Ubuntu, look with `ufw status` instead.

`./down.sh` removes the container, the key and the state.
