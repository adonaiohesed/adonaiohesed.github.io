---
title: Vim Customizing
tags: Vim
key: page-vim_customizing
categories: [Tools, MacOS]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Vim Plugin Manager Installation 
아래의 플러그인들을 설치하기 위해서 우선 플러그 매니저를 설치해야한다.
```bash
curl -fLo ~/.vim/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
```

## ~/.vimrc
```bash
set nocompatible              " be iMproved, required
filetype off                  " required

call plug#begin('~/.vim/plugged')

" 플러그인들을 여기에 추가
Plug 'preservim/nerdtree'            " 파일 탐색기
Plug 'vim-airline/vim-airline'       " 상태바 테마
Plug 'morhetz/gruvbox'               " 컬러 스킴
Plug 'dense-analysis/ale'            " 린팅
Plug 'osyo-manga/vim-anzu'
Plug 'python-mode/python-mode'
Plug 'davidhalter/jedi-vim'
Plug 'pangloss/vim-javascript'
Plug 'leafgarland/typescript-vim'

call plug#end()

autocmd FileType python setlocal expandtab shiftwidth=4 tabstop=4

" 추가 설정
colorscheme gruvbox
set background=dark

set number
set visualbell
set showmatch
set autoindent
set showmode
set laststatus=2

set smartindent
set tabstop=4
set shiftwidth=4
set expandtab

set hlsearch
set incsearch

if has("syntax")
    syntax on
endif


```

모든 것을 마친 이후에는 `:PlugInstall` 를 통해 Plug를 설치한다.