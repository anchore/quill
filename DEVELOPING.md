# Developing

There are a few useful things to know before diving into the codebase. 

## Getting started

After cloning do the following:
1. run `make bootstrap` to download go mod dependencies, create the `.tmp` dir, and download helper utilities.
2. run `make` to run linting, tests, and other verifications to make certain everything is working alright.

Checkout `make help` to see what other actions you can take.

There is data being referenced that is not checked into the source tree but instead residing in a separate store and is managed via [git-lfs](https://git-lfs.github.com/). You will need to install and initialize git-lfs to work with this repo:

```
git lfs install
```
