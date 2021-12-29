# bzdownloader
Reverse Engineered implementation of the Backblaze Personal Backup Downloader client

See [the wiki](https://github.com/kyl191/bzdownloader/wiki) for more information.

## Installation
1. [Install Poetry](https://python-poetry.org/docs/master/#installing-with-the-official-installer)
2. Checkout this repo & switch to the directory
3. Install dependencies with `poetry install`

## Use
1. Run with `poetry run bzdownloader/bzdownloader.py`
2. Login with your backblaze username & password

![login prompt](https://user-images.githubusercontent.com/499035/147623681-d5a50130-f0b2-4c38-b998-fa50c46698ea.png)

3. Enter the 2FA code if you have it setup
    
![totp prompt](https://user-images.githubusercontent.com/499035/147623708-ca6b73bd-7419-49a5-8b34-b962c22fdd5d.png)
 
4. Select the restores to download 

![selection](https://user-images.githubusercontent.com/499035/147623536-0cb9a5ff-392c-4fb7-8980-9f6fea9e5249.png)

5. Figure out where to save the files (by default the repo directory, can use tab completion for the path)

![path selection](https://user-images.githubusercontent.com/499035/147623866-665fb0a9-d681-413b-b942-b2b6da5bdb1d.png)

6. Watch the functional progress bar as the selected files get downloaded one after the other

![progress bar](https://user-images.githubusercontent.com/499035/147624085-33640e6e-9bfb-46d7-bebd-1a00f74e9a19.png)

