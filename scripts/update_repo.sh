#!/bin/bash
# HAZARUS Repository Update Script
# Fetches, compares, and pulls changes from GitHub

set -e

echo "========================================="
echo "HAZARUS Repository Update Script"
echo "========================================="
echo ""

# Check if in a git repository
if [ ! -d ".git" ]; then
    echo "Error: Not in a git repository"
    echo "Please run this script from the HAZARUS repository root"
    exit 1
fi

# Fetch latest changes from GitHub
echo "Fetching latest changes from GitHub..."
git fetch origin

# Check if there are changes to pull
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse @{u})
BASE=$(git merge-base @ @{u})

if [ $LOCAL = $REMOTE ]; then
    echo ""
    echo "========================================="
    echo "Your repository is already up to date!"
    echo "========================================="
    exit 0
elif [ $LOCAL = $BASE ]; then
    echo ""
    echo "========================================="
    echo "Changes available to pull:"
    echo "========================================="
    echo ""
    git log @{u}..@ --oneline --graph --decorate
    echo ""
    echo "-----------------------------------------"
    echo "Files that will be changed:"
    echo "-----------------------------------------"
    git diff --stat @{u}..@
    echo ""
    echo "-----------------------------------------"
    echo "Detailed changes:"
    echo "-----------------------------------------"
    git diff @{u}..@ --name-status
    echo ""
    
    # Ask for confirmation
    read -p "Do you want to pull these changes? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Pulling changes..."
        git pull origin main
        echo ""
        echo "========================================="
        echo "Update complete!"
        echo "========================================="
        echo ""
        echo "Latest commits:"
        git log --oneline -5
        echo ""
        echo "Don't forget to update dependencies if requirements.txt changed:"
        echo "  source venv/bin/activate"
        echo "  pip install -r requirements.txt"
        echo "  pip install -e ."
    else
        echo ""
        echo "Update cancelled."
    fi
elif [ $REMOTE = $BASE ]; then
    echo ""
    echo "========================================="
    echo "Your local repository has unpushed commits!"
    echo "========================================="
    echo ""
    echo "Please push or stash your local changes first:"
    echo "  git push origin main"
    echo "  # or"
    echo "  git stash"
    exit 1
else
    echo ""
    echo "========================================="
    echo "Your local and remote have diverged!"
    echo "========================================="
    echo ""
    echo "Please resolve this manually."
    exit 1
fi
