import os
import re

posts_dir = '_posts'
thumbnails_dir = 'assets/thumbnails'

def update_posts():
    for filename in os.listdir(posts_dir):
        if not filename.endswith('.md'):
            continue
            
        file_path = os.path.join(posts_dir, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Extract basename without extension
        basename = filename[:-3]
        new_image_path = f"/assets/thumbnails/{basename}.png"
        
        # Check if image field already exists
        if 'image:' in content:
            # Replace existing image field
            content = re.sub(r'image:.*', f'image: "{new_image_path}"', content)
        else:
            # Find the closing --- of the front matter
            parts = content.split('---', 2)
            if len(parts) >= 3:
                front_matter = parts[1]
                # Ensure we don't duplicate or mess up the structure
                if 'image:' not in front_matter:
                    new_front_matter = front_matter.rstrip() + f'\nimage: "{new_image_path}"\n'
                    content = '---' + new_front_matter + '---' + parts[2]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
    print("Updated all posts with thumbnail paths.")

if __name__ == "__main__":
    update_posts()
