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

" 플러그인 관리자: vim-plug 시작
call plug#begin('~/.vim/plugged')

" 기본적인 UI/UX 플러그인
Plug 'preservim/nerdtree'            " 파일 탐색기
Plug 'vim-airline/vim-airline'       " 상태바 테마
Plug 'morhetz/gruvbox'               " 컬러 스킴
Plug 'osyo-manga/vim-anzu'           " 검색 결과 하이라이트 및 이동

" 언어 관련 린팅 및 LSP/자동 완성 (선택)
" ALE는 여러 린터와 LSP를 지원하지만, Coc.nvim이 더 강력한 LSP 경험을 제공할 수 있음
Plug 'dense-analysis/ale'            " 린팅 및 일부 LSP 지원 (Coc.nvim과 대체 가능성 있음)

" Python 관련 플러그인 (Coc.nvim 사용 시 불필요)
Plug 'python-mode/python-mode'
Plug 'davidhalter/jedi-vim'

" JavaScript/TypeScript 관련 플러그인 (Coc.nvim 사용 시 불필요)
Plug 'pangloss/vim-javascript'
Plug 'leafgarland/typescript-vim'

" ===== 추천 추가 플러그인 =====
" 파일/버퍼/명령 퍼지 검색
Plug 'junegunn/fzf', { 'do': { -> fzf#install() } }
Plug 'junegunn/fzf.vim'

" 괄호/따옴표/태그 등을 쉽게 조작
Plug 'tpope/vim-surround'

" 주석 처리/해제
Plug 'tpope/vim-commentary'

" Git 통합
Plug 'tpope/vim-fugitive'

" 시작 화면 커스터마이징
Plug 'mhinz/vim-startify'

" Neovim 사용자용 (Treesitter)
" Plug 'nvim-treesitter/nvim-treesitter', {'do': ':TSUpdate'}

" Coc.nvim (강력한 LSP/자동완성, 위 언어 플러그인 대체 가능)
" Plug 'neoclide/coc.nvim', {'branch': 'release'}

call plug#end()
" 플러그인 관리자 끝

" --- 공통 설정 ---
" 색상 스킴
colorscheme gruvbox
set background=dark

" 줄 번호 표시
set number

" 시각적 피드백 (깜빡임 대신)
set visualbell

" 괄호 매칭 보여주기
set showmatch

" 자동 들여쓰기
set autoindent
set smartindent " 더 똑똑한 들여쓰기

" 현재 모드 표시 (INSERT, VISUAL 등)
set showmode

" 항상 상태바 표시
set laststatus=2

" 검색 설정
set hlsearch " 검색어 하이라이트
set incsearch " 입력하면서 검색 결과 보여주기
set smartcase " 검색시 대소문자 구별 (대문자가 포함되면 대소문자 구별, 아니면 무시)

" 탭 및 들여쓰기 설정 (전역)
set tabstop=4     " 탭 문자의 너비 (화면에 보이는 탭 크기)
set softtabstop=4 " 탭 키를 눌렀을 때의 공백 수 또는 탭 문자의 수
set shiftwidth=4  " 자동 들여쓰기/내어쓰기 시 사용될 공백(탭) 수
set expandtab     " 탭 문자를 공백으로 변환

" 스크롤 설정
set scrolloff=8 " 커서가 화면 상하단으로부터 8줄 이상 떨어지지 않게 함

" 명령어 자동 완성 설정
set wildmode=longest,list

" 파일 자동 저장 및 불러오기
set autowrite " 다른 파일로 넘어갈 때 자동 저장
set autoread  " 작업 중인 파일 외부에서 변경되었을 경우 자동으로 불러옴

" 기타 유틸리티 설정
set bs=indent,eol,start " Backspace 키로 지울 수 있는 범위
set history=1000        " 명령어 및 검색 기록 저장 개수 증가 (기본 20)
set paste               " 붙여넣기 시 들여쓰기 깨짐 방지 (pasting mode)

" 현재 커서 위치 표시 (하단 상태바)
set ruler

" 상태바 형식 정의 (airline 사용 시 일부 중복될 수 있음)
" airline이 대부분을 처리하므로 이 설정은 airline이 덮어쓸 수 있음
set statusline=\ %<%l:%v\ [%P]%=%a\ %h%m%r\ %F\

" 마지막으로 수정된 곳에 커서를 위치함
au BufReadPost *
\ if line("'\"") > 0 && line("'\"") <= line("$") |
\   exe "normal! g`\"" |
\ endif

" 파일 인코딩 설정 (대부분의 시스템에서 UTF-8 권장)
set encoding=utf-8
set fileencoding=utf-8
set fileencodings=ucs-bom,utf-8,cp949,euc-kr " 파일 읽을 때 시도할 인코딩 순서

" 구문 강조 사용 (has("syntax") 검사는 이미 플러그인에 포함된 경우 생략 가능)
if has("syntax")
    syntax on
endif

" --- 파일 타입별 추가 설정 ---
autocmd FileType python setlocal expandtab shiftwidth=4 tabstop=4 softtabstop=4
" python 파일에 대해서만 특정 탭 설정을 다시 정의하고자 할 때 사용
" (전역 설정과 동일하다면 굳이 다시 설정할 필요 없음)

" NERDTree 설정 예시
map <C-n> :NERDTreeToggle<CR> " Ctrl+n으로 NERDTree 토글
let NERDTreeShowHidden=1     " 숨김 파일 보이기
let NERDTreeIgnore=['\.pyc$', '__pycache__$', '\.git$'] " 특정 파일/폴더 무시

" Airline 설정 예시 (선택 사항)
let g:airline_theme='gruvbox' " airline 테마를 gruvbox로
```

모든 것을 마친 이후에는 `:PlugInstall` 를 통해 Plug를 설치한다.