# GD Linux profiler

Install dependencies:
```sh
pip install -r requirements.txt
```
(or whatever other way you prefer)

Symlink for quick launch:
```sh
ln -s /home/dankpc/programming/geode3/projects/profiler/gd-profile.py ~/.local/bin/gd-profile
```

Run in GD folder:
```sh
gd-profile
```

Customize frequency (default 1000) or wine path (default `$(which wine)`):
```sh
gd-profile -F --wine-path /usr/bin/wine
```
