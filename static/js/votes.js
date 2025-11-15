document.addEventListener('DOMContentLoaded', function() {
    // Handle voting on posts page
    const postCards = document.querySelectorAll('.post-card');
    
    postCards.forEach(card => {
        const postId = card.getAttribute('data-post-id');
        if (!postId) return;
        
        const voteButtons = card.querySelectorAll('.vote-btn');
        
        voteButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                const voteType = this.getAttribute('data-vote');
                handleVote(postId, voteType, this);
            });
        });
    });
    
    // Handle voting on single post view page
    const singlePostVoteForms = document.querySelectorAll('.post-full .post-actions form');
    singlePostVoteForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const postId = this.action.split('/').filter(Boolean).pop();
            const action = this.querySelector('input[name="action"]').value;
            const voteType = action === 'up' ? 'up' : 'down';
            
            handleVote(postId, voteType, this.querySelector('button'));
        });
    });
});

function handleVote(postId, voteType, buttonElement) {
    fetch(`/post/${postId}/vote`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ vote: voteType })
    })
    .then(response => {
        if (response.status === 403) {
            throw new Error('You must be logged in to vote');
        }
        if (!response.ok) {
            throw new Error('Vote failed');
        }
        return response.json();
    })
    .then(data => {
        // Update vote counts in the UI
        updateVoteCounts(postId, data.upvotes, data.downvotes, data.user_vote);
        
        // Optional: Show visual feedback
        showVoteFeedback(buttonElement, voteType);
    })
    .catch(error => {
        console.error('Error:', error);
        if (error.message === 'You must be logged in to vote') {
            alert('Please login to vote on posts');
            window.location.href = '/login';
        } else {
            alert('Failed to register vote. Please try again.');
        }
    });
}

function updateVoteCounts(postId, upvotes, downvotes, userVote) {
    // Find the post card
    const postCard = document.querySelector(`.post-card[data-post-id="${postId}"]`);
    if (!postCard) {
        // Maybe we're on the single post view page
        updateSinglePostVotes(upvotes, downvotes);
        return;
    }
    
    // Update upvote count
    const upvoteBtn = postCard.querySelector('.vote-btn[data-vote="up"]');
    const downvoteBtn = postCard.querySelector('.vote-btn[data-vote="down"]');
    
    if (upvoteBtn) {
        const upvoteCount = upvoteBtn.querySelector('.count');
        if (upvoteCount) {
            upvoteCount.textContent = upvotes;
        }
        
        // Update active state
        if (userVote === 1) {
            upvoteBtn.classList.add('active');
            downvoteBtn.classList.remove('active');
        } else if (userVote === -1) {
            upvoteBtn.classList.remove('active');
            downvoteBtn.classList.add('active');
        } else {
            upvoteBtn.classList.remove('active');
            downvoteBtn.classList.remove('active');
        }
    }
    
    if (downvoteBtn) {
        const downvoteCount = downvoteBtn.querySelector('.count');
        if (downvoteCount) {
            downvoteCount.textContent = downvotes;
        }
    }
}

function updateSinglePostVotes(upvotes, downvotes) {
    // Update votes on single post view page
    const upvoteBtn = document.querySelector('.post-full .post-actions button[type="submit"]');
    const downvoteBtn = document.querySelectorAll('.post-full .post-actions button[type="submit"]')[1];
    
    if (upvoteBtn) {
        upvoteBtn.textContent = `↑ Upvote (${upvotes})`;
    }
    if (downvoteBtn) {
        downvoteBtn.textContent = `↓ Downvote (${downvotes})`;
    }
}

function showVoteFeedback(button, voteType) {
    // Add a brief animation/feedback
    button.style.transform = 'scale(1.2)';
    setTimeout(() => {
        button.style.transform = 'scale(1)';
    }, 200);
}